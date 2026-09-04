// agent/core/forensicTaskEngine.js

import {
    createJob,
    updateJob,
    isCancelled,
    cancelJob,
    removeJob
} from "./jobStore.js";

import {
    runForensicScan
} from "./forensicEngine.js";


/* =====================================================
   START FORENSIC TASK
===================================================== */

export async function startForensicTask(socket, job) {

    const {
        jobId,
        disk,
        devicePath,
        caseId,
        examiner
    } = job;

    const sourceDisk = devicePath || disk;

    console.log("");
    console.log("================================");
    console.log("      FORENSIC SCAN RECEIVED");
    console.log("================================");
    console.log("Job ID :", jobId);
    console.log("Case ID:", caseId);
    console.log("Disk   :", sourceDisk);
    console.log("Agent  :", job.agentId || "unknown");
    console.log("================================");


    /* -------------------------------------------------
       VALIDATION
    ------------------------------------------------- */

    if (!jobId) {
        throw new Error("Missing forensic job ID");
    }

    if (!caseId) {
        throw new Error("Missing case ID");
    }

    if (!sourceDisk) {
        throw new Error("Missing forensic source disk");
    }


    /* -------------------------------------------------
       CREATE LOCAL JOB
    ------------------------------------------------- */

    createJob(jobId, "FORENSIC");


    /* -------------------------------------------------
       PROGRESS EMITTER
    ------------------------------------------------- */

    const emitProgress = (
        progress,
        message,
        status = "RUNNING"
    ) => {

        const safeProgress = Math.max(
            0,
            Math.min(100, Number(progress) || 0)
        );

        updateJob(
            jobId,
            {
                progress: safeProgress,
                status
            }
        );


        socket.emit(
            "forensic-progress",
            {
                deviceId: job.agentId || null,

                jobId,

                operationId:
                    job.operationId || null,

                caseId,

                progress: safeProgress,

                message,

                status,

                timestamp:
                    new Date().toISOString()
            }
        );

    };


    /* -------------------------------------------------
       START
    ------------------------------------------------- */

    try {

        emitProgress(
            1,
            "Forensic task accepted.",
            "RUNNING"
        );


        /* ---------------------------------------------
           CHECK CANCELLATION
        --------------------------------------------- */

        if (isCancelled(jobId)) {

            emitProgress(
                0,
                "Forensic task cancelled before execution.",
                "CANCELLED"
            );

            removeJob(jobId);

            return {
                success: false,
                cancelled: true,
                jobId
            };
        }


        /* ---------------------------------------------
           RUN FORENSIC ENGINE
        --------------------------------------------- */

        const result = await runForensicScan({

            jobId,

            disk: sourceDisk,

            devicePath: sourceDisk,

            caseId,

            examiner,

            agentId:
                job.agentId || null,

            operationId:
                job.operationId || null,

            socket,

            /*
             * Allow forensicEngine to check
             * cancellation if it supports it.
             */
            isCancelled: () =>
                isCancelled(jobId),

            /*
             * Progress callback for the
             * forensic engine.
             */
            onProgress: (
                progress,
                message
            ) => {

                if (isCancelled(jobId)) {
                    return;
                }

                emitProgress(
                    progress,
                    message ||
                    "Forensic scan in progress.",
                    "RUNNING"
                );

            }

        });


        /* ---------------------------------------------
           CHECK CANCELLATION AFTER SCAN
        --------------------------------------------- */

        if (isCancelled(jobId)) {

            emitProgress(
                0,
                "Forensic task cancelled.",
                "CANCELLED"
            );

            removeJob(jobId);

            return {
                success: false,
                cancelled: true,
                jobId
            };
        }


        /* ---------------------------------------------
           COMPLETE
        --------------------------------------------- */

        updateJob(
            jobId,
            {
                progress: 100,
                status: "completed",
                result,
                completedAt:
                    new Date()
            }
        );


        socket.emit(
            "forensic-complete",
            {
                success: true,

                deviceId:
                    job.agentId || null,

                jobId,

                operationId:
                    job.operationId || null,

                caseId,

                status:
                    "COMPLETED",

                progress: 100,

                result,

                timestamp:
                    new Date().toISOString()
            }
        );


        console.log("");
        console.log(
            "✅ FORENSIC SCAN COMPLETED"
        );

        console.log(
            "   Job ID:",
            jobId
        );


        removeJob(jobId);


        return {
            success: true,
            jobId,
            result
        };

    }


    /* -------------------------------------------------
       ERROR
    ------------------------------------------------- */

    catch (error) {

        console.error("");
        console.error(
            "❌ FORENSIC TASK FAILED"
        );

        console.error(
            "Job ID:",
            jobId
        );

        console.error(
            "Error:",
            error.message
        );


        updateJob(
            jobId,
            {
                status: "failed",

                error:
                    error.message,

                completedAt:
                    new Date()
            }
        );


        socket.emit(
            "forensic-error",
            {
                success: false,

                deviceId:
                    job.agentId || null,

                jobId,

                operationId:
                    job.operationId || null,

                caseId,

                status:
                    "FAILED",

                error:
                    error.message,

                code:
                    error.code ||
                    "FORENSIC_TASK_FAILED",

                timestamp:
                    new Date().toISOString()
            }
        );


        removeJob(jobId);


        return {
            success: false,
            jobId,
            error: error.message
        };
    }
}


/* =====================================================
   CANCEL FORENSIC TASK
===================================================== */

export async function cancelForensicTask(jobId) {

    if (!jobId) {

        throw new Error(
            "Missing forensic job ID"
        );
    }


    console.log("");
    console.log(
        "⛔ Cancelling forensic task:",
        jobId
    );


    /*
     * Mark the local job as cancelled.
     *
     * The forensic engine can check
     * isCancelled(jobId) while running.
     */

    const cancelled =
        cancelJob(jobId);


    if (!cancelled) {

        console.log(
            "⚠️ Forensic job not found:",
            jobId
        );

        return {
            success: false,
            jobId,
            message:
                "Forensic job not found"
        };
    }


    updateJob(
        jobId,
        {
            status: "CANCEL_REQUESTED"
        }
    );


    console.log(
        "✅ Forensic cancellation requested:",
        jobId
    );


    return {
        success: true,
        jobId,
        status:
            "CANCEL_REQUESTED"
    };
}


/* =====================================================
   DEFAULT EXPORT
===================================================== */

export default {
    startForensicTask,
    cancelForensicTask
};