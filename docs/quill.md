### Available Macros
The severity levels, ordered from lowest to highest:

* LOG_TRACE(logger, fmt, ...): Extremely detailed diagnostic info (usually disabled in release builds).

* LOG_DEBUG(logger, fmt, ...): Debugging details for developers during troubleshooting.

* LOG_INFO(logger, fmt, ...): General operational events (e.g., "Server started", "Connection established").

* LOG_WARNING(logger, fmt, ...): Non-critical anomalies that don't stop execution (e.g., "Retrying packet transmission").

* LOG_ERROR(logger, fmt, ...): Recoverable errors or failures (e.g., "Failed to bind socket").

* LOG_CRITICAL(logger, fmt, ...): Severe system failures that usually precede an application abort.

### When to Use Each Level
* LOG_TRACE / LOG_DEBUG: Use when tracing low-level execution paths, such as entering a function, dumping byte buffers, or tracking state machine transitions.

* LOG_INFO: Use for major lifecycle milestones or significant structural events (e.g., configuration loaded, peer connected, shutdown initiated).

* LOG_WARNING: Use when something unexpected happens, but the application can safely handle or bypass it (e.g., a malformed packet was received and dropped).

* LOG_ERROR: Use when an operation fails and an expected action cannot be completed (e.g., a read/write timeout, an authentication failure, or a failed system call like bind or listen).

* LOG_CRITICAL: Use when the application has encountered a fatal condition and cannot continue operating safely.


## RELEASE AND DEBUG BUILDS

## Macros active in the debug build
In the debug build, CMakeLists.txt sets the macro to QUILL_COMPILE_ACTIVE_LOG_LEVEL_DEBUG. This means every standard logging macro is fully compiled into the binary:
* LOG_TRACE_L3(...)
* LOG_TRACE_L2(...)
* LOG_TRACE_L1(...)
* LOG_DEBUG(...)
* LOG_INFO(...)
* LOG_WARNING(...)
* LOG_ERROR(...)
* LOG_CRITICAL(...)

## Macros active in the release build
macro becomes QUILL_COMPILE_ACTIVE_LOG_LEVEL_INFO. Active macros:
* LOG_INFO(...)
* LOG_WARNING(...)
* LOG_ERROR(...)
* LOG_CRITICAL(...)