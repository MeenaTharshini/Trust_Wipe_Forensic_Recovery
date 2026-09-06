
(async () => {
    try {
        console.log("=================================");
        console.log("       TrustWipe Agent Starting");
        console.log("=================================");

        console.log("[Agent] Loading Socket.IO client...");

        await import("./core/socketClient.js");

        console.log("[Agent] Socket client started successfully.");

    } catch (error) {
        console.error("");
        console.error("=================================");
        console.error("❌ TRUSTWIPE AGENT STARTUP FAILED");
        console.error("=================================");

        console.error(
            error?.stack ||
            error?.message ||
            error
        );

        console.error("=================================");
        console.error("");

        process.exit(1);
    }
})();
