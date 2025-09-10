const fs = require('fs');
const path = require('path');

class Logger {
    constructor() {
        this.logDir = path.join(process.cwd(), 'logs');
        this.ensureLogDirectory();
    }

    // Ensure log directory exists
    ensureLogDirectory() {
        if (!fs.existsSync(this.logDir)) {
            fs.mkdirSync(this.logDir, { recursive: true });
        }
    }

    // Get current date string for log files
    getCurrentDateString() {
        return new Date().toISOString().split('T')[0];
    }

    // Get timestamp string
    getTimestamp() {
        return new Date().toISOString();
    }

    // Format log message
    formatLogMessage(level, message, meta = {}) {
        const timestamp = this.getTimestamp();
        const logEntry = {
            timestamp,
            level: level.toUpperCase(),
            message,
            ...meta
        };

        return JSON.stringify(logEntry);
    }

    // Write log to file
    writeLog(level, message, meta = {}) {
        const logMessage = this.formatLogMessage(level, message, meta);
        const logFile = path.join(this.logDir, `${this.getCurrentDateString()}.log`);

        fs.appendFileSync(logFile, logMessage + '\n', 'utf8');
    }

    // Public log methods
    info(message, meta = {}) {
        console.log(this.formatLogMessage('info', message, meta));
        this.writeLog('info', message, meta);
    }

    error(message, meta = {}) {
        console.error(this.formatLogMessage('error', message, meta));
        this.writeLog('error', message, meta);
    }

    warn(message, meta = {}) {
        console.warn(this.formatLogMessage('warn', message, meta));
        this.writeLog('warn', message, meta);
    }

    debug(message, meta = {}) {
        console.debug(this.formatLogMessage('debug', message, meta));
        this.writeLog('debug', message, meta);
    }
}

module.exports = new Logger();
