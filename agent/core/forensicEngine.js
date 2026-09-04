// agent/core/forensicEngine.js

import fs from "fs";
import path from "path";
import crypto from "crypto";
import { spawn } from "child_process";
import os from "os";

const FORENSIC_ROOT =
    process.env.FORENSIC_AGENT_ROOT ||
    path.join(process.cwd(), "forensic");

const EVIDENCE_ROOT =
    path.join(FORENSIC_ROOT, "evidence");

const RECOVERED_ROOT =
    path.join(FORENSIC_ROOT, "recovered");

function ensureDirectories() {
    fs.mkdirSync(EVIDENCE_ROOT, { recursive: true });
    fs.mkdirSync(RECOVERED_ROOT, { recursive: true });
}

function sha256File(filePath) {
    return new Promise((resolve, reject) => {
        const hash = crypto.createHash("sha256");
        const stream = fs.createReadStream(filePath);

        stream.on("data", chunk => hash.update(chunk));

        stream.on("end", () => {
            resolve(hash.digest("hex"));
        });

        stream.on("error", reject);
    });
}

function runPython(args, onOutput) {
    return new Promise((resolve, reject) => {

        const pythonCommand =
            os.platform() === "win32"
                ? "python"
                : "python3";

        const process = spawn(
            pythonCommand,
            args,
            {
                cwd: path.resolve(
                    process.env.FORENSIC_PYTHON_ROOT ||
                    path.join(process.cwd(), "forensic_recovery")
                )
            }
        );

        let stdout = "";
        let stderr = "";

        process.stdout.on("data", data => {
            const text = data.toString();

            stdout += text;

            if (onOutput) {
                onOutput(text);
            }
        });

        process.stderr.on("data", data => {
            const text = data.toString();

            stderr += text;

            if (onOutput) {
                onOutput(text);
            }
        });

        process.on("error", reject);

        process.on("close", code => {

            if (code !== 0) {
                return reject(
                    new Error(
                        `Forensic engine exited with code ${code}: ${stderr}`
                    )
                );
            }

            resolve({
                stdout,
                stderr
            });
        });
    });
}

export async function runForensicScan({
    jobId,
    disk,
    caseId,
    examiner,
    socket
}) {

    ensureDirectories();

    if (!disk) {
        throw new Error("No disk selected.");
    }

    if (!caseId) {
        throw new Error("Case ID is required.");
    }

    if (!examiner) {
        throw new Error("Examiner is required.");
    }

    const outputDirectory =
        path.join(
            RECOVERED_ROOT,
            String(jobId)
        );

    fs.mkdirSync(outputDirectory, {
        recursive: true
    });

    const emitProgress = (
        progress,
        message
    ) => {

        socket.emit(
            "forensic-progress",
            {
                jobId,
                progress,
                message,
                status: "RUNNING"
            }
        );
    };

    emitProgress(
        5,
        "Preparing forensic acquisition..."
    );

    /*
     * IMPORTANT:
     * The physical device identifier is supplied
     * by the trusted agent discovery result.
     */

    const devicePath =
        disk.devicePath;

    if (!devicePath) {
        throw new Error(
            "Physical device path is missing."
        );
    }

    emitProgress(
        10,
        "Validating selected device..."
    );

    /*
     * Run your existing Python forensic engine.
     *
     * Keep the Python engine responsible for
     * acquisition / carving / metadata analysis.
     */

    const result =
        await runPython(
            [
                "cli.py",
                "scan",

                "--input",
                devicePath,

                "--output",
                outputDirectory,

                "--case",
                caseId,

                "--examiner",
                examiner,

                "--json"
            ],
            text => {

                socket.emit(
                    "forensic-output",
                    {
                        jobId,
                        output: text
                    }
                );
            }
        );

    emitProgress(
        90,
        "Finalizing forensic results..."
    );

    let parsedResult = {};

    try {
        parsedResult =
            JSON.parse(
                result.stdout.trim()
            );
    }
    catch {
        parsedResult = {
            rawOutput:
                result.stdout
        };
    }

    emitProgress(
        100,
        "Forensic recovery completed."
    );

    return {
        jobId,
        caseId,
        examiner,
        disk,
        outputDirectory,
        result: parsedResult
    };
}