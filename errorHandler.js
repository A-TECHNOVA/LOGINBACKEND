const logger = require('../utils/logger');

class ErrorHandler {
    // Main error handling middleware
    handle(err, req, res, next) {
        let error = { ...err };
        error.message = err.message;

        // Log error
        logger.error('Error occurred:', {
            message: err.message,
            stack: err.stack,
            url: req.originalUrl,
            method: req.method,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            userId: req.user?.userId,
            studentId: req.user?.studentId
        });

        // Mongoose bad ObjectId
        if (err.name === 'CastError') {
            const message = 'Invalid ID format';
            error = this.createError(message, 400);
        }

        // Mongoose duplicate key
        if (err.code === 11000) {
            const duplicateField = Object.keys(err.keyValue)[0];
            const message = `Duplicate value for ${duplicateField}`;
            error = this.createError(message, 400);
        }

        // Mongoose validation error
        if (err.name === 'ValidationError') {
            const message = Object.values(err.errors).map(val => val.message).join(', ');
            error = this.createError(message, 400);
        }

        // JWT errors
        if (err.name === 'JsonWebTokenError') {
            const message = 'Invalid token';
            error = this.createError(message, 401);
        }

        if (err.name === 'TokenExpiredError') {
            const message = 'Token expired';
            error = this.createError(message, 401);
        }

        // Multer errors (file upload)
        if (err.code === 'LIMIT_FILE_SIZE') {
            const message = 'File too large';
            error = this.createError(message, 400);
        }

        if (err.code === 'LIMIT_FILE_COUNT') {
            const message = 'Too many files';
            error = this.createError(message, 400);
        }

        if (err.code === 'LIMIT_UNEXPECTED_FILE') {
            const message = 'Unexpected file field';
            error = this.createError(message, 400);
        }

        // Rate limiting error
        if (err.status === 429) {
            const message = 'Too many requests, please try again later';
            error = this.createError(message, 429);
        }

        // Send error response
        res.status(error.statusCode || 500).json({
            success: false,
            message: error.message || 'Internal server error',
            ...(process.env.NODE_ENV === 'development' && {
                stack: err.stack,
                error: err
            })
        });
    }

    // Create custom error
    createError(message, statusCode) {
        const error = new Error(message);
        error.statusCode = statusCode;
        return error;
    }

    // 404 handler
    notFound(req, res, next) {
        const message = `Route ${req.originalUrl} not found`;
        const error = this.createError(message, 404);
        next(error);
    }

    // Async error handler wrapper
    asyncHandler(fn) {
        return (req, res, next) => {
            Promise.resolve(fn(req, res, next)).catch(next);
        };
    }

    // Database error handler
    databaseError(err) {
        if (err.name === 'MongoError' || err.name === 'MongooseError') {
            logger.error('Database error:', err);
            return this.createError('Database operation failed', 500);
        }
        return err;
    }

    // Validation error handler
    validationError(errors) {
        const message = errors.map(error => error.msg).join(', ');
        return this.createError(message, 400);
    }

    // Authentication error handler
    authError(message = 'Authentication failed') {
        return this.createError(message, 401);
    }

    // Authorization error handler
    authzError(message = 'Insufficient permissions') {
        return this.createError(message, 403);
    }

    // Custom application errors
    badRequest(message = 'Bad request') {
        return this.createError(message, 400);
    }

    conflict(message = 'Conflict') {
        return this.createError(message, 409);
    }

    tooManyRequests(message = 'Too many requests') {
        return this.createError(message, 429);
    }

    internalError(message = 'Internal server error') {
        return this.createError(message, 500);
    }
}

const errorHandlerInstance = new ErrorHandler();

module.exports = errorHandlerInstance.handle.bind(errorHandlerInstance);