#ifndef QRYPTSECURITY_LOGGING_H
#define QRYPTSECURITY_LOGGING_H

#include <sstream>
#include <iostream>
#include <string>
#include <mutex>
#include <memory>
#include <iomanip>

namespace QryptSecurity 
{
namespace logging
{
    ///<summary>Describes the severity of a log</summary>
    enum class LogLevel {
        QRYPTLIB_LOG_LEVEL_TRACE,
        QRYPTLIB_LOG_LEVEL_DEBUG,
        QRYPTLIB_LOG_LEVEL_INFO,
        QRYPTLIB_LOG_LEVEL_WARNING,
        QRYPTLIB_LOG_LEVEL_ERROR,
        QRYPTLIB_LOG_LEVEL_DISABLE
    };

    static const char* LogLevelNames[] = {
        "Trace", "Debug", "Info", "Warning", "Error", "Disable"
    };

    ///<summary>Get the text name of a LogLevel value</summary>
    /// <param name="logLevel">The LogLevel to get the text name for.</param>
    inline const char* getLogLevelText(LogLevel logLevel)
    {
        return LogLevelNames[static_cast<int>(logLevel)];
    }

    ///<summary>
    /// Abstract class representing an object that consumers of QryptLib can implement
    /// and then call ILogWriter::registerCallback passing in an instance of their 
    /// implementation to receive logging messages from QryptLib.
    ///</summary>
    class ILogMessageReceiver {
    public:
        /// <summary>
        /// Receive a log message from QryptLib.
        /// <summary>
        /// <param name="message">A log message from QryptLib.</param>
        /// <param name="logLevel">The LogLevel the message was produced at.</param>
        virtual void receive(std::string const& message, LogLevel logLevel) = 0;
    };

    ///<summary>
    /// Abstract class representing an object that consumes logs and writes log text 
    /// to some configured location(s) in a thread-safe manner.
    ///</summary>
    class ILogWriter {
    protected:
        std::mutex _Mutex;
        ILogMessageReceiver *_LogMessageReceiver = nullptr;

    public:
        ILogWriter() {}
        virtual ~ILogWriter() = default;

        /// <summary>
        /// Logs the message at the desired LogLevel.
        /// </summary>
        /// <param name="message">The log message to output.</param>
        /// <param name="logLevel">The level to output the log message at.</param>
        virtual void logMessage(const std::string& message, LogLevel logLevel) = 0;

        /// <summary>
        /// Registers an ILogMessageReceiver to receive log messages from QryptLib.
        ///
        /// Only one ILogMessageReceiver will be active at one time.
        /// </summary>
        /// <param name="receiver">The ILogMessageReceiver instance to receive log 
        /// messages from QyptLib.</param>
        virtual void registerCallback(ILogMessageReceiver *receiver) = 0;

        /// <summary>
        /// Unregisters the currently active ILogMessageReceiver.
        ///
        /// Only one ILogMessageReceiver will be active at one time.
        /// </summary>
        virtual void unregisterCallback() = 0;

        /// <summary>
        /// Enable logs to be written to a rolling file.
        ///
        /// File logging is disabled by default.
        /// <summary>
        /// <param name="filePath">The path and filename of the file to log to.
        ///                        Defaults to QryptLib.log at the current executable location.
        /// </param>
        /// <param name="maxFileSizeInBytes">The size, at which, the file will be rolled. 
        ///                                  Defaults to 1 MB.
        /// </param>
        #define MAX_FILE_SIZE_DEFAULT 1048576   // 1 MB
        virtual void enableFileLogging(std::string filePath = "qryptlib.log", uint32_t maxFileSizeInBytes = MAX_FILE_SIZE_DEFAULT) = 0;

        /// <summary>
        /// Disable logging to a file.
        ///
        /// File logging is disabled by default.
        /// <summary>
        virtual void disableFileLogging() = 0;

        /// <summary>
        /// Set the level to log at.
        /// 
        /// The logging levels in ascending order are:
        /// QRYPTLIB_LOG_LEVEL_TRACE
        /// QRYPTLIB_LOG_LEVEL_DEBUG
        /// QRYPTLIB_LOG_LEVEL_INFO
        /// QRYPTLIB_LOG_LEVEL_WARNING
        /// QRYPTLIB_LOG_LEVEL_ERROR
        /// QRYPTLIB_LOG_LEVEL_DISABLE
        ///
        /// Example: setLogLevel(LogLevel::QRYPTLIB_LOG_LEVEL_INFO)
        /// Logs submitted at QRYPTLIB_LOG_LEVEL_INFO, QRYPTLIB_LOG_LEVEL_WARNING 
        /// and QRYPTLIB_LOG_LEVEL_ERROR will be sent to the appropriate logging outputs.
        /// Logs submitted at QRYPTLIB_LOG_LEVEL_DEBUG will be ignored.
        /// </summary>
        /// <param name="logLevel">The LogLevel to set logging at.</param>
        virtual void setLogLevel(LogLevel logLevel) = 0;
    };

    /// <summary>
    /// Get the singleton instance of the ILogWriter.
    /// 
    /// A default ILogWriter is provided by QryptLib.
    /// </summary>
    std::shared_ptr<ILogWriter> getLogWriter();

    /// <summary>
    /// Set the singleton instance of the ILogWriter.
    ///
    /// A default ILogWriter is provided by QryptLib.
    /// </summary>
    void setLogWriter(std::shared_ptr<ILogWriter> logWriter);

    ///<summary>Write a trace log to the active ILogWriter</summary>
    inline void logTrace(const std::string& message) { getLogWriter()->logMessage(message, LogLevel::QRYPTLIB_LOG_LEVEL_TRACE); }

    ///<summary>Write a debug log to the active ILogWriter</summary>
    inline void logDebug(const std::string& message) { getLogWriter()->logMessage(message, LogLevel::QRYPTLIB_LOG_LEVEL_DEBUG); }

    ///<summary>Write an info log to the active ILogWriter</summary>
    inline void logInfo(const std::string& message) { getLogWriter()->logMessage(message, LogLevel::QRYPTLIB_LOG_LEVEL_INFO); }

    ///<summary>Write a warning log to the active ILogWriter</summary>
    inline void logWarning(const std::string& message) { getLogWriter()->logMessage(message, LogLevel::QRYPTLIB_LOG_LEVEL_WARNING); }

    ///<summary>Write an error log to the active ILogWriter</summary>
    inline void logError(const std::string& message) { getLogWriter()->logMessage(message, LogLevel::QRYPTLIB_LOG_LEVEL_ERROR); }

}
}
#endif