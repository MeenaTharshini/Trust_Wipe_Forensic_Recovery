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

    /* -------------------------------------------------
       BASIC JOB DATA
    ------------------------------------------------- */

    const {
        jobId,
        disk,
        devicePath,
        caseId,
        examiner
    } = job || {};


    /* -------------------------------------------------
       NORMALIZE FORENSIC DEVICE PATH
    ------------------------------------------------- */

    const resolvedDevicePath =
        typeof devicePath === "string" &&
        devicePath.trim()
            ? devicePath.trim()

            : typeof disk === "string" &&
              disk.trim()
                ? disk.trim()

                : typeof disk?.devicePath === "string" &&
                  disk.devicePath.trim()
                    ? disk.devicePath.trim()

                    : typeof disk?.device_path === "string" &&
                      disk.device_path.trim()
                        ? disk.device_path.trim()

                        : null;


    /* -------------------------------------------------
       NORMALIZE SOURCE DISK
    ------------------------------------------------- */

    const sourceDisk =
        resolvedDevicePath
            ? {
                devicePath:
                    resolvedDevicePath,

                device_path:
                    resolvedDevicePath
            }
            : null;


    /* -------------------------------------------------
       LOG FORENSIC REQUEST
    ------------------------------------------------- */

    console.log("");

    console.log(
        "================================"
    );

    console.log(
        "      FORENSIC SCAN RECEIVED"
    );

    console.log(
        "================================"
    );

    console.log(
        "Job ID :",
        jobId || "unknown"
    );

    console.log(
        "Case ID:",
        caseId || "unknown"
    );

    console.log(
        "Disk   :",
        sourceDisk || "unknown"
    );

    console.log(
        "Device Path:",
        resolvedDevicePath || "unknown"
    );

    console.log(
        "Evidence:",
        job?.evidence?.fileName ||
        job?.evidence?.file_name ||
        job?.fileName ||
        "unknown"
    );

    console.log(
        "Agent  :",
        job?.agentId || "unknown"
    );

    console.log(
        "================================"
    );


    /* -------------------------------------------------
       VALIDATION
    ------------------------------------------------- */

    if (!jobId) {

        throw new Error(
            "Missing forensic job ID"
        );
    }


    if (!caseId) {

        throw new Error(
            "Missing case ID"
        );
    }


    if (!resolvedDevicePath) {

        const error =
            new Error(
                "Missing forensic source disk/devicePath"
            );

        error.code =
            "FORENSIC_DEVICE_PATH_MISSING";

        throw error;
    }


    /* -------------------------------------------------
       CREATE LOCAL JOB
    ------------------------------------------------- */

    createJob(
        jobId,
        "FORENSIC"
    );


    /* -------------------------------------------------
       PROGRESS EMITTER
    ------------------------------------------------- */

    const emitProgress = (
        progress,
        message,
        status = "RUNNING"
    ) => {

        const safeProgress =
            Math.max(
                0,
                Math.min(
                    100,
                    Number(progress) || 0
                )
            );


        updateJob(
            jobId,
            {
                progress:
                    safeProgress,

                status
            }
        );


        socket.emit(
            "forensic-progress",
            {

                deviceId:
                    job?.agentId ||
                    null,

                jobId,

                operationId:
                    job?.operationId ||
                    null,

                caseId,

                progress:
                    safeProgress,

                message,

                status,

                timestamp:
                    new Date().toISOString()
            }
        );
    };


    /* =================================================
       START FORENSIC PROCESSING
    ================================================= */

    try {

        /* ---------------------------------------------
           INITIAL PROGRESS
        --------------------------------------------- */

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


            removeJob(
                jobId
            );


            return {
                success: false,
                cancelled: true,
                jobId
            };
        }


        /* ---------------------------------------------
           RUN FORENSIC ENGINE
        --------------------------------------------- */

        const result =
            await runForensicScan({

                jobId,

                disk:
                    sourceDisk,

                devicePath:
                    resolvedDevicePath,

                caseId,

                examiner,

                agentId:
                    job?.agentId ||
                    null,

                operationId:
                    job?.operationId ||
                    null,

                socket,


                /* -------------------------------------
                   CANCELLATION CALLBACK
                ------------------------------------- */

                isCancelled: () =>
                    isCancelled(
                        jobId
                    ),


                /* -------------------------------------
                   PROGRESS CALLBACK
                ------------------------------------- */

                onProgress: (
                    progress,
                    message
                ) => {

                    if (
                        isCancelled(
                            jobId
                        )
                    ) {
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

        if (
            isCancelled(
                jobId
            )
        ) {

            emitProgress(
                0,
                "Forensic task cancelled.",
                "CANCELLED"
            );


            removeJob(
                jobId
            );


            return {
                success: false,
                cancelled: true,
                jobId
            };
        }


        /* ---------------------------------------------
           UPDATE LOCAL JOB
        --------------------------------------------- */

        updateJob(
            jobId,
            {

                progress:
                    100,

                status:
                    "completed",

                result,

                completedAt:
                    new Date()
            }
        );


        /* ---------------------------------------------
           SEND COMPLETION TO BACKEND
        --------------------------------------------- */

        socket.emit(
            "forensic-complete",
            {

                success:
                    true,

                deviceId:
                    job?.agentId ||
                    null,

                jobId,

                operationId:
                    job?.operationId ||
                    null,

                caseId,

                status:
                    "COMPLETED",

                progress:
                    100,

                result,

                timestamp:
                    new Date().toISOString()
            }
        );


        /* ---------------------------------------------
           LOG COMPLETION
        --------------------------------------------- */

        console.log("");

        console.log(
            "================================"
        );

        console.log(
            "✅ FORENSIC SCAN COMPLETED"
        );

        console.log(
            "   Job ID:",
            jobId
        );

        console.log(
            "   Device:",
            resolvedDevicePath
        );

        console.log(
            "================================"
        );


        /* ---------------------------------------------
           REMOVE LOCAL JOB
        --------------------------------------------- */

        removeJob(
            jobId
        );


        return {
            success:
                true,

            jobId,

            result
        };

    }


    /* =================================================
       FORENSIC ERROR
    ================================================= */

    catch (error) {

        console.error("");

        console.error(
            "================================"
        );

        console.error(
            "❌ FORENSIC TASK FAILED"
        );

        console.error(
            "================================"
        );

        console.error(
            "Job ID:",
            jobId
        );

        console.error(
            "Device:",
            resolvedDevicePath ||
            "unknown"
        );

        console.error(
            "Error:",
            error?.message ||
            error
        );


        /* ---------------------------------------------
           UPDATE LOCAL JOB
        --------------------------------------------- */

        updateJob(
            jobId,
            {

                status:
                    "failed",

                error:
                    error?.message ||
                    "Forensic task failed.",

                completedAt:
                    new Date()
            }
        );


        /* ---------------------------------------------
           SEND ERROR TO BACKEND
        --------------------------------------------- */

        socket.emit(
            "forensic-error",
            {

                success:
                    false,

                deviceId:
                    job?.agentId ||
                    null,

                jobId,

                operationId:
                    job?.operationId ||
                    null,

                caseId,

                status:
                    "FAILED",

                error:
                    error?.message ||
                    "Forensic task failed.",

                code:
                    error?.code ||
                    "FORENSIC_TASK_FAILED",

                timestamp:
                    new Date().toISOString()
            }
        );


        /* ---------------------------------------------
           REMOVE LOCAL JOB
        --------------------------------------------- */

        removeJob(
            jobId
        );


        return {

            success:
                false,

            jobId,

            error:
                error?.message ||
                "Forensic task failed."
        };
    }
}


/* =====================================================
   CANCEL FORENSIC TASK
===================================================== */

export async function cancelForensicTask(
    jobId
) {

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


    /* -------------------------------------------------
       MARK JOB AS CANCELLED
    ------------------------------------------------- */

    const cancelled =
        cancelJob(
            jobId
        );


    if (!cancelled) {

        console.log(
            "⚠️ Forensic job not found:",
            jobId
        );


        return {

            success:
                false,

            jobId,

            message:
                "Forensic job not found"
        };
    }


    /* -------------------------------------------------
       UPDATE STATUS
    ------------------------------------------------- */

    updateJob(
        jobId,
        {

            status:
                "CANCEL_REQUESTED"
        }
    );


    console.log(
        "✅ Forensic cancellation requested:",
        jobId
    );


    return {

        success:
            true,

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