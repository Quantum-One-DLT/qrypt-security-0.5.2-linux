#ifndef QRYPTSECURITY_EXCEPTIONS_H
#define QRYPTSECURITY_EXCEPTIONS_H

#include <exception>
#include <string>

class QryptSecurityException : public std::exception {
  private:
    std::string _ExceptionMsg;

  public:
    /// <summary>
    /// Constructs QryptSecurityException
    /// </summary>
    ///
    /// <param name="errMsg">The error message</param>
    QryptSecurityException(std::string message) {
        _ExceptionMsg = message;
    }

    /// <summary>
    /// Destroys QryptSecurityException
    /// </summary>
    ~QryptSecurityException() = default;

    /// <summary>
    /// Returns the error message
    /// </summary>
    const char *what() const noexcept override { return _ExceptionMsg.c_str(); };
};


class UnknownError : public QryptSecurityException {
  public:
    UnknownError(std::string message) : QryptSecurityException(message) {}
};

class InvalidArgument : public QryptSecurityException {
  public:
    InvalidArgument(std::string message) : QryptSecurityException(message) {}
};

class SystemError : public QryptSecurityException {
  public:
    SystemError(std::string message) : QryptSecurityException(message) {}
};

class DeviceSecretFailed : public QryptSecurityException {
  public:
    DeviceSecretFailed(std::string message) : QryptSecurityException(message) {}
};

class CacheNotReady : public QryptSecurityException {
  public:
    CacheNotReady(std::string message) : QryptSecurityException(message) {}
};

class CannotDownload : public QryptSecurityException {
  public:
    CannotDownload(std::string message) : QryptSecurityException(message) {}
};

class DataCorrupted : public QryptSecurityException {
  public:
    DataCorrupted(std::string message) : QryptSecurityException(message) {}
};

class RandomPoolExpired : public QryptSecurityException {
  public:
    RandomPoolExpired(std::string message) : QryptSecurityException(message) {}
};

class RandomPoolInactive : public QryptSecurityException {
  public:
    RandomPoolInactive(std::string message) : QryptSecurityException(message) {}
};

#endif
