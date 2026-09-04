// agent/core/jobStore.js


/* =====================================================
   TRUSTWIPE AGENT JOB STORE

   Stores active wipe and forensic jobs locally
   inside the TrustWipe Agent.

   Supported job types:
   - WIPE
   - FORENSIC
===================================================== */


const activeJobs = new Map();


/* =====================================================
   CREATE JOB
===================================================== */

export const createJob = (
    id,
    type = "WIPE",
    metadata = {}
) => {

    if (!id) {

        throw new Error(
            "Job ID is required."
        );

    }


    const now = new Date();


    const job = {

        id,

        type,

        status: "running",

        cancelled: false,

        progress: 0,

        message: "Job started.",

        createdAt: now,

        startedAt: now,

        updatedAt: now,

        completedAt: null,

        cancelledAt: null,

        error: null,

        result: null,

        ...metadata

    };


    activeJobs.set(
        id,
        job
    );


    console.log(
        `▶ ${type} job created:`,
        id
    );


    return job;

};


/* =====================================================
   UPDATE JOB
===================================================== */

export const updateJob = (
    id,
    updates = {}
) => {

    const job =
        activeJobs.get(id);


    if (!job) {

        console.warn(
            "⚠️ Job not found:",
            id
        );

        return null;

    }


    Object.assign(
        job,
        updates,
        {
            updatedAt:
                new Date()
        }
    );


    return job;

};


/* =====================================================
   UPDATE JOB PROGRESS
===================================================== */

export const updateJobProgress = (
    id,
    progress,
    message = ""
) => {

    const job =
        activeJobs.get(id);


    if (!job) {

        console.warn(
            "⚠️ Job not found:",
            id
        );

        return null;

    }


    let safeProgress =
        Number(progress);


    if (
        Number.isNaN(
            safeProgress
        )
    ) {

        safeProgress = 0;

    }


    safeProgress =
        Math.max(
            0,
            Math.min(
                100,
                safeProgress
            )
        );


    job.progress =
        safeProgress;


    if (message) {

        job.message =
            message;

    }


    job.updatedAt =
        new Date();


    return job;

};


/* =====================================================
   SET JOB STATUS
===================================================== */

export const setJobStatus = (
    id,
    status,
    message = ""
) => {

    const job =
        activeJobs.get(id);


    if (!job) {

        return null;

    }


    job.status =
        status;


    if (message) {

        job.message =
            message;

    }


    job.updatedAt =
        new Date();


    /*
     * Automatically record completion
     */

    if (
        status === "completed" ||
        status === "COMPLETED"
    ) {

        job.progress = 100;

        job.completedAt =
            new Date();

    }


    /*
     * Automatically record cancellation
     */

    if (
        status === "cancelled" ||
        status === "CANCELLED"
    ) {

        job.cancelled = true;

        job.cancelledAt =
            new Date();

    }


    return job;

};


/* =====================================================
   SET JOB RESULT
===================================================== */

export const setJobResult = (
    id,
    result
) => {

    const job =
        activeJobs.get(id);


    if (!job) {

        return null;

    }


    job.result =
        result;


    job.updatedAt =
        new Date();


    return job;

};


/* =====================================================
   SET JOB ERROR
===================================================== */

export const setJobError = (
    id,
    error
) => {

    const job =
        activeJobs.get(id);


    if (!job) {

        return null;

    }


    const message =
        error instanceof Error
            ? error.message
            : String(error);


    job.status =
        "failed";


    job.error =
        message;


    job.message =
        message;


    job.updatedAt =
        new Date();


    job.completedAt =
        new Date();


    return job;

};


/* =====================================================
   CANCEL JOB
===================================================== */

export const cancelJob = (
    id
) => {

    const job =
        activeJobs.get(id);


    if (!job) {

        console.warn(
            "⚠️ Cannot cancel. Job not found:",
            id
        );

        return null;

    }


    /*
     * Do not cancel an already
     * completed job.
     */

    if (
        job.status === "completed" ||
        job.status === "COMPLETED"
    ) {

        console.warn(
            "⚠️ Job already completed:",
            id
        );

        return job;

    }


    job.cancelled =
        true;


    job.status =
        "cancelled";


    job.message =
        "Job cancelled.";


    job.cancelledAt =
        new Date();


    job.updatedAt =
        new Date();


    console.log(
        "⛔ Job cancelled:",
        id
    );


    return job;

};


/* =====================================================
   CHECK CANCEL STATUS
===================================================== */

export const isCancelled = (
    id
) => {

    return (
        activeJobs.get(id)
            ?.cancelled === true
    );

};


/* =====================================================
   CHECK JOB EXISTS
===================================================== */

export const hasJob = (
    id
) => {

    return activeJobs.has(
        id
    );

};


/* =====================================================
   GET JOB
===================================================== */

export const getJob = (
    id
) => {

    return (
        activeJobs.get(id) ||
        null
    );

};


/* =====================================================
   GET JOB TYPE
===================================================== */

export const getJobType = (
    id
) => {

    return (
        activeJobs.get(id)
            ?.type ||
        null
    );

};


/* =====================================================
   LIST ACTIVE JOBS
===================================================== */

export const listJobs = () => {

    return Array.from(
        activeJobs.values()
    );

};


/* =====================================================
   LIST JOBS BY TYPE
===================================================== */

export const listJobsByType = (
    type
) => {

    return Array.from(
        activeJobs.values()
    )
    .filter(
        job =>
            job.type === type
    );

};


/* =====================================================
   LIST RUNNING JOBS
===================================================== */

export const listRunningJobs = () => {

    return Array.from(
        activeJobs.values()
    )
    .filter(
        job =>
            job.status === "running"
    );

};


/* =====================================================
   REMOVE JOB
===================================================== */

export const removeJob = (
    id
) => {

    const job =
        activeJobs.get(id);


    if (job) {

        console.log(
            "🗑️ Job removed:",
            id
        );

    }


    activeJobs.delete(
        id
    );

};


/* =====================================================
   CLEAR ALL JOBS
===================================================== */

export const clearJobs = () => {

    activeJobs.clear();


    console.log(
        "🧹 All agent jobs cleared."
    );

};


/* =====================================================
   GET JOB COUNT
===================================================== */

export const getJobCount = () => {

    return activeJobs.size;

};


/* =====================================================
   GET JOB STORE SNAPSHOT
===================================================== */

export const getJobStoreSnapshot = () => {

    return {

        total:
            activeJobs.size,

        jobs:
            listJobs()

    };

};


/* =====================================================
   DEFAULT EXPORT
===================================================== */

export default {

    createJob,

    updateJob,

    updateJobProgress,

    setJobStatus,

    setJobResult,

    setJobError,

    cancelJob,

    isCancelled,

    hasJob,

    getJob,

    getJobType,

    listJobs,

    listJobsByType,

    listRunningJobs,

    removeJob,

    clearJobs,

    getJobCount,

    getJobStoreSnapshot

};