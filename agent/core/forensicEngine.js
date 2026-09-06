// agent/core/forensicEngine.js

import fs from "fs";
import path from "path";
import crypto from "crypto";
import { spawn } from "child_process";
import os from "os";
import { fileURLToPath } from "url";


/*
=========================================================
 TRUSTWIPE FORENSIC ENGINE
 Agent-side forensic execution engine

 Responsibilities:
 - Execute Python forensic engine locally on Agent
 - Work with physical device paths
 - Create isolated output directory per job
 - Stream Python stdout/stderr
 - Report progress
 - Support cancellation
 - Enforce execution timeout
 - Parse JSON result
 - Hash generated forensic files

 IMPORTANT:
 Physical forensic acquisition happens on the
 customer's TrustWipe Agent, NOT on Render.
=========================================================
*/


/* =====================================================
   PATH CONFIGURATION
===================================================== */

const __filename =
    fileURLToPath(import.meta.url);

const __dirname =
    path.dirname(__filename);


/*
   agent/core/forensicEngine.js

   __dirname = .../agent/core

   Agent root = .../agent
*/

const AGENT_ROOT =
    process.env.TRUSTWIPE_AGENT_ROOT ||
    path.resolve(
        __dirname,
        ".."
    );


/* =====================================================
   FORENSIC PYTHON ROOT
===================================================== */

const FORENSIC_PYTHON_ROOT =
    process.env.FORENSIC_PYTHON_ROOT ||
    path.join(
        AGENT_ROOT,
        "forensic_recovery"
    );


/* =====================================================
   LOCAL FORENSIC STORAGE
===================================================== */

const FORENSIC_ROOT =
    process.env.FORENSIC_AGENT_ROOT ||
    path.join(
        AGENT_ROOT,
        "forensic"
    );

const EVIDENCE_ROOT =
    path.join(
        FORENSIC_ROOT,
        "evidence"
    );

const RECOVERED_ROOT =
    path.join(
        FORENSIC_ROOT,
        "recovered"
    );

const REPORTS_ROOT =
    path.join(
        FORENSIC_ROOT,
        "reports"
    );


/* =====================================================
   CONFIGURATION
===================================================== */

const DEFAULT_TIMEOUT =
    6 * 60 * 60 * 1000; // 6 hours

const FORENSIC_TIMEOUT_MS =
    Number(
        process.env.FORENSIC_TIMEOUT_MS
    ) || DEFAULT_TIMEOUT;


/*
   Maximum stdout/stderr retained in memory.
*/

const MAX_OUTPUT_BYTES =
    Number(
        process.env.FORENSIC_MAX_OUTPUT_BYTES
    ) || 10 * 1024 * 1024;


/* =====================================================
   DIRECTORY INITIALIZATION
===================================================== */

function ensureDirectories() {

    fs.mkdirSync(
        FORENSIC_ROOT,
        {
            recursive: true
        }
    );

    fs.mkdirSync(
        EVIDENCE_ROOT,
        {
            recursive: true
        }
    );

    fs.mkdirSync(
        RECOVERED_ROOT,
        {
            recursive: true
        }
    );

    fs.mkdirSync(
        REPORTS_ROOT,
        {
            recursive: true
        }
    );
}


/* =====================================================
   SAFE STRING
===================================================== */

function safeString(
    value,
    fallback = ""
) {

    if (
        value === undefined ||
        value === null
    ) {
        return fallback;
    }

    return String(
        value
    ).trim();
}


/* =====================================================
   SHA-256 FILE HASH
===================================================== */

function sha256File(
    filePath
) {

    return new Promise(
        (
            resolve,
            reject
        ) => {

            const hash =
                crypto.createHash(
                    "sha256"
                );

            const stream =
                fs.createReadStream(
                    filePath
                );


            stream.on(
                "data",
                chunk => {

                    hash.update(
                        chunk
                    );

                }
            );


            stream.on(
                "end",
                () => {

                    resolve(
                        hash.digest(
                            "hex"
                        )
                    );

                }
            );


            stream.on(
                "error",
                reject
            );

        }
    );
}


/* =====================================================
   RECURSIVE FILE HASHING
===================================================== */

async function hashDirectory(
    directory
) {

    const files = [];


    if (
        !fs.existsSync(
            directory
        )
    ) {

        return files;
    }


    async function walk(
        currentDirectory
    ) {

        const entries =
            await fs.promises.readdir(
                currentDirectory,
                {
                    withFileTypes:
                        true
                }
            );


        for (
            const entry
            of entries
        ) {

            const fullPath =
                path.join(
                    currentDirectory,
                    entry.name
                );


            if (
                entry.isDirectory()
            ) {

                await walk(
                    fullPath
                );

                continue;
            }


            if (
                !entry.isFile()
            ) {

                continue;
            }


            try {

                const stat =
                    await fs.promises.stat(
                        fullPath
                    );

                const hash =
                    await sha256File(
                        fullPath
                    );


                files.push({

                    fileName:
                        entry.name,

                    relativePath:
                        path.relative(
                            directory,
                            fullPath
                        ),

                    size:
                        stat.size,

                    sha256:
                        hash

                });

            }
            catch (
                error
            ) {

                files.push({

                    fileName:
                        entry.name,

                    relativePath:
                        path.relative(
                            directory,
                            fullPath
                        ),

                    error:
                        error.message

                });

            }
        }
    }


    await walk(
        directory
    );


    return files;
}


/* =====================================================
   PYTHON EXECUTABLE
===================================================== */

function getPythonCommand() {

    /*
       Explicit Python executable.
    */

    if (
        process.env.FORENSIC_PYTHON_EXE
    ) {

        return path.resolve(
            process.env.FORENSIC_PYTHON_EXE
        );
    }


    /*
       Bundled Python.
    */

    if (
        os.platform() ===
        "win32"
    ) {

        const bundledPython =
            path.join(
                AGENT_ROOT,
                "runtime",
                "python",
                "python.exe"
            );


        if (
            fs.existsSync(
                bundledPython
            )
        ) {

            return bundledPython;
        }


        /*
           Development fallback.
        */

        return "python";
    }


    /*
       Linux/macOS development.
    */

    return "python3";
}


/* =====================================================
   PYTHON EXECUTION
===================================================== */

function runPython(
    args,
    {
        onOutput,
        isCancelled,
        timeoutMs =
            FORENSIC_TIMEOUT_MS
    } = {}
) {

    return new Promise(
        (
            resolve,
            reject
        ) => {

            const pythonCommand =
                getPythonCommand();


            const pythonRoot =
                path.resolve(
                    FORENSIC_PYTHON_ROOT
                );


            /*
               Validate forensic Python root.
            */

            if (
                !fs.existsSync(
                    pythonRoot
                )
            ) {

                return reject(
                    new Error(
                        `Forensic Python directory not found: ${pythonRoot}`
                    )
                );
            }


            /*
               Validate cli.py.
            */

            const cliPath =
                path.join(
                    pythonRoot,
                    "cli.py"
                );


            if (
                !fs.existsSync(
                    cliPath
                )
            ) {

                return reject(
                    new Error(
                        `Forensic CLI not found: ${cliPath}`
                    )
                );
            }


            /*
               Prepare arguments.
            */

            const pythonArgs =
                [...args];


            if (
                pythonArgs[0] ===
                "cli.py"
            ) {

                pythonArgs[0] =
                    cliPath;
            }


            console.log(
                "[Forensics] Python:",
                pythonCommand
            );

            console.log(
                "[Forensics] Python root:",
                pythonRoot
            );

            console.log(
                "[Forensics] Arguments:",
                pythonArgs
            );


            let stdout = "";

            let stderr = "";

            let settled = false;

            let timedOut = false;

            let cancelled = false;


            /*
               Start Python process.
            */

            const child =
                spawn(
                    pythonCommand,
                    pythonArgs,
                    {

                        cwd:
                            pythonRoot,

                        windowsHide:
                            os.platform() ===
                            "win32",

                        shell:
                            false,

                        env: {

                            ...process.env,

                            PYTHONUNBUFFERED:
                                "1"
                        }

                    }
                );


            /* =================================================
               OUTPUT LIMITER
            ================================================= */

            function appendOutput(
                target,
                text
            ) {

                const combined =
                    target +
                    text;


                if (
                    Buffer.byteLength(
                        combined,
                        "utf8"
                    ) <=
                    MAX_OUTPUT_BYTES
                ) {

                    return combined;
                }


                const buffer =
                    Buffer.from(
                        combined,
                        "utf8"
                    );


                return buffer
                    .subarray(
                        Math.max(
                            0,
                            buffer.length -
                                MAX_OUTPUT_BYTES
                        )
                    )
                    .toString(
                        "utf8"
                    );
            }


            /* =================================================
               FINISH ERROR
            ================================================= */

            function finishError(
                error
            ) {

                if (
                    settled
                ) {

                    return;
                }


                settled =
                    true;


                reject(
                    error
                );
            }


            /* =================================================
               FINISH SUCCESS
            ================================================= */

            function finishSuccess(
                result
            ) {

                if (
                    settled
                ) {

                    return;
                }


                settled =
                    true;


                resolve(
                    result
                );
            }


            /* =================================================
               CANCELLATION TIMER
            ================================================= */

            const cancellationTimer =
                setInterval(
                    () => {

                        try {

                            if (
                                typeof isCancelled ===
                                    "function" &&
                                isCancelled()
                            ) {

                                cancelled =
                                    true;


                                clearInterval(
                                    cancellationTimer
                                );


                                try {

                                    child.kill(
                                        "SIGTERM"
                                    );

                                }
                                catch {}


                                /*
                                   Force termination if
                                   necessary.
                                */

                                setTimeout(
                                    () => {

                                        if (
                                            !child.killed
                                        ) {

                                            try {

                                                child.kill(
                                                    "SIGKILL"
                                                );

                                            }
                                            catch {}
                                        }

                                    },
                                    3000
                                );
                            }

                        }
                        catch {}
                    },
                    1000
                );


            /* =================================================
               TIMEOUT
            ================================================= */

            const timeoutTimer =
                setTimeout(
                    () => {

                        if (
                            settled
                        ) {

                            return;
                        }


                        timedOut =
                            true;


                        console.error(
                            "[Forensics] Python execution timed out."
                        );


                        try {

                            child.kill(
                                "SIGTERM"
                            );

                        }
                        catch {}


                        setTimeout(
                            () => {

                                if (
                                    !settled &&
                                    !child.killed
                                ) {

                                    try {

                                        child.kill(
                                            "SIGKILL"
                                        );

                                    }
                                    catch {}
                                }

                            },
                            5000
                        );

                    },
                    timeoutMs
                );


            /* =================================================
               STDOUT
            ================================================= */

            child.stdout.on(
                "data",
                data => {

                    const text =
                        data.toString();


                    stdout =
                        appendOutput(
                            stdout,
                            text
                        );


                    if (
                        typeof onOutput ===
                        "function"
                    ) {

                        onOutput(
                            text,
                            "stdout"
                        );
                    }
                }
            );


            /* =================================================
               STDERR
            ================================================= */

            child.stderr.on(
                "data",
                data => {

                    const text =
                        data.toString();


                    stderr =
                        appendOutput(
                            stderr,
                            text
                        );


                    if (
                        typeof onOutput ===
                        "function"
                    ) {

                        onOutput(
                            text,
                            "stderr"
                        );
                    }
                }
            );


            /* =================================================
               PROCESS ERROR
            ================================================= */

            child.on(
                "error",
                error => {

                    clearTimeout(
                        timeoutTimer
                    );

                    clearInterval(
                        cancellationTimer
                    );


                    finishError(
                        error
                    );
                }
            );


            /* =================================================
               PROCESS CLOSE
            ================================================= */

            child.on(
                "close",
                code => {

                    clearTimeout(
                        timeoutTimer
                    );

                    clearInterval(
                        cancellationTimer
                    );


                    if (
                        cancelled
                    ) {

                        return finishError(
                            Object.assign(
                                new Error(
                                    "Forensic scan was cancelled."
                                ),
                                {
                                    code:
                                        "FORENSIC_CANCELLED"
                                }
                            )
                        );
                    }


                    if (
                        timedOut
                    ) {

                        return finishError(
                            Object.assign(
                                new Error(
                                    `Forensic engine timed out after ${timeoutMs} ms.`
                                ),
                                {
                                    code:
                                        "FORENSIC_TIMEOUT"
                                }
                            )
                        );
                    }


                    if (
                        code !== 0
                    ) {

                        return finishError(
                            Object.assign(
                                new Error(
                                    `Forensic engine exited with code ${code}: ${stderr}`
                                ),
                                {

                                    code:
                                        "FORENSIC_PROCESS_FAILED",

                                    exitCode:
                                        code,

                                    stdout,

                                    stderr

                                }
                            )
                        );
                    }


                    finishSuccess({

                        stdout,

                        stderr,

                        exitCode:
                            code

                    });
                }
            );
        }
    );
}


/* =====================================================
   PROGRESS PARSER
===================================================== */

function parseProgressLine(
    line
) {

    if (
        !line
    ) {

        return null;
    }


    /*
       Supported:

       PROGRESS:10
       PROGRESS:50:Scanning
       {"progress":50,"message":"Scanning"}
    */

    const progressMatch =
        line.match(
            /PROGRESS\s*:\s*(\d{1,3})(?:\s*:\s*(.*))?/i
        );


    if (
        progressMatch
    ) {

        return {

            progress:
                Math.max(
                    0,
                    Math.min(
                        100,
                        Number(
                            progressMatch[1]
                        )
                    )
                ),

            message:
                progressMatch[2] ||
                "Forensic scan in progress."
        };
    }


    /*
       JSON progress message.
    */

    try {

        const parsed =
            JSON.parse(
                line
            );


        if (
            parsed &&
            typeof parsed.progress ===
                "number"
        ) {

            return {

                progress:
                    Math.max(
                        0,
                        Math.min(
                            100,
                            parsed.progress
                        )
                    ),

                message:
                    parsed.message ||
                    "Forensic scan in progress."
            };
        }

    }
    catch {}


    return null;
}


/* =====================================================
   PYTHON RESULT PARSER
===================================================== */

function parsePythonResult(
    stdout
) {

    const text =
        safeString(
            stdout
        );


    if (
        !text
    ) {

        return {};
    }


    /*
       First attempt:
       Entire stdout is JSON.
    */

    try {

        return JSON.parse(
            text
        );

    }
    catch {}


    /*
       Python may print logs before JSON.
    */

    const lines =
        text
            .split(
                /\r?\n/
            )
            .map(
                line =>
                    line.trim()
            )
            .filter(
                Boolean
            );


    /*
       Search from the end.
    */

    for (
        let i =
            lines.length - 1;

        i >= 0;

        i--
    ) {

        const line =
            lines[i];


        try {

            const parsed =
                JSON.parse(
                    line
                );


            if (
                parsed &&
                typeof parsed ===
                    "object"
            ) {

                return parsed;
            }

        }
        catch {}
    }


    /*
       Preserve raw output.
    */

    return {

        rawOutput:
            stdout

    };
}


/* =====================================================
   MAIN FORENSIC SCAN
===================================================== */

export async function runForensicScan({

    jobId,

    disk,

    devicePath,

    caseId,

    examiner,

    agentId,

    operationId,

    socket,

    isCancelled,

    onProgress

}) {

    ensureDirectories();


    /* =================================================
       BASIC VALIDATION
    ================================================= */

    if (
        !jobId
    ) {

        throw new Error(
            "Forensic job ID is required."
        );
    }


    if (
        !caseId
    ) {

        throw new Error(
            "Case ID is required."
        );
    }


    if (
        !examiner
    ) {

        throw new Error(
            "Examiner is required."
        );
    }


    /* =================================================
       RESOLVE DEVICE PATH
    ================================================= */

    let resolvedDevicePath =
        typeof devicePath ===
        "string"
            ? devicePath.trim()
            : null;


    /*
       Fallback to disk.
    */

    if (
        !resolvedDevicePath &&
        disk
    ) {

        if (
            typeof disk ===
            "string"
        ) {

            resolvedDevicePath =
                disk.trim();

        }
        else if (
            typeof disk.devicePath ===
            "string"
        ) {

            resolvedDevicePath =
                disk.devicePath.trim();

        }
        else if (
            typeof disk.device_path ===
            "string"
        ) {

            resolvedDevicePath =
                disk.device_path.trim();

        }
    }


    /* =================================================
       VALIDATE DEVICE PATH
    ================================================= */

    if (
        !resolvedDevicePath
    ) {

        const error =
            new Error(
                "Physical device path is missing."
            );

        error.code =
            "FORENSIC_DEVICE_PATH_MISSING";

        throw error;
    }


    /*
       Normalize Windows physical path.

       Expected:

       \\\\.\\PhysicalDrive0
    */

    if (
        os.platform() ===
            "win32" &&
        resolvedDevicePath
            .toLowerCase()
            .startsWith(
                "\\\\.\\"
            ) === false
    ) {

        console.warn(
            "[Forensics] Device path does not use Windows physical-device format:",
            resolvedDevicePath
        );
    }


    /* =================================================
       JOB OUTPUT DIRECTORY
    ================================================= */

    const safeJobId =
        safeString(
            jobId
        ).replace(
            /[^a-zA-Z0-9._-]/g,
            "_"
        );


    const outputDirectory =
        path.join(
            RECOVERED_ROOT,
            safeJobId
        );


    fs.mkdirSync(
        outputDirectory,
        {
            recursive:
                true
        }
    );


    /* =================================================
       PROGRESS
    ================================================= */

    const emitProgress =
        (
            progress,
            message
        ) => {

            const safeProgress =
                Math.max(
                    0,
                    Math.min(
                        100,
                        Number(
                            progress
                        ) || 0
                    )
                );


            const safeMessage =
                message ||
                "Forensic scan in progress.";


            /*
               Agent → Backend.
            */

            if (
                socket &&
                typeof socket.emit ===
                    "function"
            ) {

                socket.emit(
                    "forensic-progress",
                    {

                        deviceId:
                            agentId ||
                            null,

                        jobId,

                        operationId:
                            operationId ||
                            null,

                        caseId,

                        progress:
                            safeProgress,

                        message:
                            safeMessage,

                        status:
                            "RUNNING",

                        timestamp:
                            new Date()
                                .toISOString()

                    }
                );
            }


            /*
               Task engine callback.
            */

            if (
                typeof onProgress ===
                    "function"
            ) {

                try {

                    onProgress(
                        safeProgress,
                        safeMessage
                    );

                }
                catch (
                    error
                ) {

                    console.warn(
                        "[Forensics] Progress callback failed:",
                        error.message
                    );
                }
            }
        };


    /* =================================================
       INITIAL PROGRESS
    ================================================= */

    emitProgress(
        5,
        "Preparing forensic acquisition..."
    );


    /* =================================================
       CANCELLATION CHECK
    ================================================= */

    if (
        typeof isCancelled ===
            "function" &&
        isCancelled()
    ) {

        emitProgress(
            0,
            "Forensic scan cancelled."
        );


        const error =
            new Error(
                "Forensic scan was cancelled."
            );

        error.code =
            "FORENSIC_CANCELLED";

        throw error;
    }


    emitProgress(
        10,
        "Validating selected device..."
    );


    /* =================================================
       FORENSIC ENGINE LOG
    ================================================= */

    console.log("");

    console.log(
        "========================================"
    );

    console.log(
        "       TRUSTWIPE FORENSIC ENGINE"
    );

    console.log(
        "========================================"
    );

    console.log(
        "Job ID       :",
        jobId
    );

    console.log(
        "Case ID      :",
        caseId
    );

    console.log(
        "Examiner     :",
        examiner
    );

    console.log(
        "Agent ID     :",
        agentId ||
        "unknown"
    );

    console.log(
        "Operation ID :",
        operationId ||
        "unknown"
    );

    console.log(
        "Device       :",
        resolvedDevicePath
    );

    console.log(
        "Output       :",
        outputDirectory
    );

    console.log(
        "========================================"
    );


    /* =================================================
       PYTHON ARGUMENTS
    ================================================= */

    const pythonArgs = [

        "cli.py",

        "scan",

        "--input",
        resolvedDevicePath,

        "--output",
        outputDirectory,

        "--case",
        String(
            caseId
        ),

        "--examiner",
        String(
            examiner
        ),

        "--json"

    ];


    console.log(
        "[Forensics] Physical acquisition target:",
        resolvedDevicePath
    );


    /* =================================================
       PYTHON EXECUTION
    ================================================= */

    let lastProgress =
        10;


    const result =
        await runPython(
            pythonArgs,
            {

                isCancelled,

                timeoutMs:
                    FORENSIC_TIMEOUT_MS,

                onOutput:
                    (
                        text,
                        stream
                    ) => {

                        /*
                           Forward Python output.
                        */

                        if (
                            socket &&
                            typeof socket.emit ===
                                "function"
                        ) {

                            socket.emit(
                                "forensic-output",
                                {

                                    jobId,

                                    operationId:
                                        operationId ||
                                        null,

                                    output:
                                        text,

                                    stream:
                                        stream ||
                                        "stdout"

                                }
                            );
                        }


                        /*
                           Parse progress.
                        */

                        const lines =
                            String(
                                text
                            )
                                .split(
                                    /\r?\n/
                                );


                        for (
                            const line
                            of lines
                        ) {

                            const progress =
                                parseProgressLine(
                                    line
                                );


                            if (
                                progress
                            ) {

                                lastProgress =
                                    Math.max(
                                        lastProgress,
                                        progress.progress
                                    );


                                emitProgress(
                                    lastProgress,
                                    progress.message
                                );
                            }
                        }
                    }
            }
        );


    /* =================================================
       FINALIZATION
    ================================================= */

    emitProgress(
        90,
        "Finalizing forensic results..."
    );


    /* =================================================
       CANCELLATION CHECK
    ================================================= */

    if (
        typeof isCancelled ===
            "function" &&
        isCancelled()
    ) {

        emitProgress(
            0,
            "Forensic scan cancelled."
        );


        const error =
            new Error(
                "Forensic scan was cancelled."
            );

        error.code =
            "FORENSIC_CANCELLED";

        throw error;
    }


    /* =================================================
       PARSE PYTHON RESULT
    ================================================= */

    const parsedResult =
        parsePythonResult(
            result.stdout
        );


    /* =================================================
       HASH FORENSIC OUTPUTS
    ================================================= */

    emitProgress(
        93,
        "Calculating forensic output hashes..."
    );


    let outputFiles =
        [];


    try {

        outputFiles =
            await hashDirectory(
                outputDirectory
            );

    }
    catch (
        error
    ) {

        console.warn(
            "[Forensics] Output hashing failed:",
            error.message
        );
    }


    /* =================================================
       ARTIFACT COUNTS
    ================================================= */

    const artifactsFound =
        outputFiles.length;


    let totalOutputBytes =
        0;


    for (
        const file
        of outputFiles
    ) {

        if (
            Number.isFinite(
                file.size
            )
        ) {

            totalOutputBytes +=
                file.size;
        }
    }


    /* =================================================
       FINAL PROGRESS
    ================================================= */

    emitProgress(
        100,
        "Forensic scan completed."
    );


    /* =================================================
       COMPLETION LOG
    ================================================= */

    console.log("");

    console.log(
        "========================================"
    );

    console.log(
        "✅ FORENSIC SCAN COMPLETED"
    );

    console.log(
        "Job ID:",
        jobId
    );

    console.log(
        "Device:",
        resolvedDevicePath
    );

    console.log(
        "Artifacts:",
        artifactsFound
    );

    console.log(
        "Recovered Bytes:",
        totalOutputBytes
    );

    console.log(
        "========================================"
    );


    /* =================================================
       RETURN STRUCTURED RESULT
    ================================================= */

    return {

        success:
            true,

        jobId,

        operationId:
            operationId ||
            null,

        agentId:
            agentId ||
            null,

        caseId,

        examiner,

        devicePath:
            resolvedDevicePath,

        disk:
            sourceDiskForResult(
                disk,
                resolvedDevicePath
            ),

        outputDirectory,

        artifactsFound,

        outputBytes:
            totalOutputBytes,

        outputFiles,

        result:
            parsedResult,

        startedAt:
            null,

        completedAt:
            new Date()
                .toISOString()

    };
}


/* =====================================================
   SOURCE DISK RESULT HELPER
===================================================== */

function sourceDiskForResult(
    disk,
    resolvedDevicePath
) {

    if (
        disk &&
        typeof disk ===
            "object"
    ) {

        return {

            ...disk,

            devicePath:
                resolvedDevicePath,

            device_path:
                resolvedDevicePath
        };
    }


    return {

        devicePath:
            resolvedDevicePath,

        device_path:
            resolvedDevicePath
    };
}


/* =====================================================
   OPTIONAL EXPORTS
===================================================== */

export {
    sha256File,
    hashDirectory,
    getPythonCommand
};