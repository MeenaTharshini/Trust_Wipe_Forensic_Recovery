(async () => {
    try {
        console.log("=================================");
        console.log("     TrustWipe Agent Starting");
        console.log("=================================");

        await import("./core/socketClient.js");

    } catch (error) {
        console.error("❌ TrustWipe Agent failed to start:");
        console.error(error);
        process.exit(1);
    }
})();