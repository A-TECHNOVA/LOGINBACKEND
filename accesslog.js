const mongoose = require('mongoose');

const accessLogSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: false 
    },
    studentId: {
        type: String,
        required: true,
        uppercase: true
    },
    action: {
        type: String,
        required: [true, 'Action is required'],
        enum: [
            'LOGIN_SUCCESS',
            'LOGIN_FAILED',
            'LOGOUT',
            'PASSWORD_RESET_REQUEST',
            'PASSWORD_RESET_SUCCESS',
            'PASSWORD_CHANGE',
            'ACCOUNT_LOCKED',
            'PROFILE_UPDATE',
            'ROLE_CHANGE'
        ]
    },
    result: {
        type: String,
        required: [true, 'Result is required'],
        enum: ['SUCCESS', 'FAILURE', 'ERROR']
    },
    details: {
        reason: {
            type: String 
        },
        oldRole: {
            type: String 
        },
        newRole: {
            type: String 
        },
        changes: {
            type: mongoose.Schema.Types.Mixed 
        }
    },
    session: {
        ip: {
            type: String,
            required: true
        },
        userAgent: {
            type: String,
            required: true
        },
        browser: {
            type: String
        },
        os: {
            type: String
        },
        device: {
            type: String
        }
    },
    location: {
        country: {
            type: String
        },
        region: {
            type: String
        },
        city: {
            type: String
        }
    },
    timestamp: {
        type: Date,
        default: Date.now,
        index: true
    }
}, {
    timestamps: false 
});


accessLogSchema.index({ userId: 1, timestamp: -1 });
accessLogSchema.index({ studentId: 1, timestamp: -1 });
accessLogSchema.index({ action: 1, timestamp: -1 });
accessLogSchema.index({ 'session.ip': 1, timestamp: -1 });
accessLogSchema.index({ result: 1, timestamp: -1 });


accessLogSchema.index({ timestamp: 1 }, { expireAfterSeconds: 365 * 24 * 60 * 60 });


accessLogSchema.statics.logAccess = async function(logData) {
    try {
        const log = new this(logData);
        await log.save();
        return log;
    } catch (error) {
        console.error('Error logging access:', error);
       
    }
};


accessLogSchema.statics.getUserLoginHistory = function(userId, limit = 10) {
    return this.find({
        userId: userId,
        action: { $in: ['LOGIN_SUCCESS', 'LOGIN_FAILED'] }
    })
    .sort({ timestamp: -1 })
    .limit(limit)
    .select('action result session.ip session.userAgent timestamp details.reason');
};


accessLogSchema.statics.getFailedLoginAttempts = function(studentId, timeWindow = 15) {
    const since = new Date(Date.now() - timeWindow * 60 * 1000);
    
    return this.countDocuments({
        studentId: studentId,
        action: 'LOGIN_FAILED',
        timestamp: { $gte: since }
    });
};


accessLogSchema.statics.getLoginStats = function(dateRange = 7) {
    const since = new Date(Date.now() - dateRange * 24 * 60 * 60 * 1000);
    
    return this.aggregate([
        {
            $match: {
                action: { $in: ['LOGIN_SUCCESS', 'LOGIN_FAILED'] },
                timestamp: { $gte: since }
            }
        },
        {
            $group: {
                _id: {
                    date: { $dateToString: { format: "%Y-%m-%d", date: "$timestamp" } },
                    action: "$action"
                },
                count: { $sum: 1 }
            }
        },
        {
            $group: {
                _id: "$_id.date",
                successful: {
                    $sum: { $cond: [{ $eq: ["$_id.action", "LOGIN_SUCCESS"] }, "$count", 0] }
                },
                failed: {
                    $sum: { $cond: [{ $eq: ["$_id.action", "LOGIN_FAILED"] }, "$count", 0] }
                }
            }
        },
        {
            $sort: { _id: 1 }
        }
    ]);
};


accessLogSchema.statics.getSuspiciousActivity = function(limit = 50) {
    return this.aggregate([
        {
            $match: {
                action: 'LOGIN_FAILED',
                timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } 
            }
        },
        {
            $group: {
                _id: {
                    ip: "$session.ip",
                    studentId: "$studentId"
                },
                attempts: { $sum: 1 },
                lastAttempt: { $max: "$timestamp" },
                userAgents: { $addToSet: "$session.userAgent" }
            }
        },
        {
            $match: {
                attempts: { $gte: 3 }
            }
        },
        {
            $sort: { attempts: -1, lastAttempt: -1 }
        },
        {
            $limit: limit
        }
    ]);
};


accessLogSchema.methods.parseUserAgent = function() {
    const ua = this.session.userAgent;
    if (!ua) return;

    
    let browser = 'Unknown';
    let os = 'Unknown';
    let device = 'Desktop';

 
    if (ua.includes('Chrome')) browser = 'Chrome';
    else if (ua.includes('Firefox')) browser = 'Firefox';
    else if (ua.includes('Safari')) browser = 'Safari';
    else if (ua.includes('Edge')) browser = 'Edge';

  
    if (ua.includes('Windows')) os = 'Windows';
    else if (ua.includes('Mac')) os = 'macOS';
    else if (ua.includes('Linux')) os = 'Linux';
    else if (ua.includes('Android')) os = 'Android';
    else if (ua.includes('iOS')) os = 'iOS';

 
    if (ua.includes('Mobile') || ua.includes('Android') || ua.includes('iPhone')) {
        device = 'Mobile';
    } else if (ua.includes('Tablet') || ua.includes('iPad')) {
        device = 'Tablet';
    }

    this.session.browser = browser;
    this.session.os = os;
    this.session.device = device;
};


accessLogSchema.pre('save', function(next) {
    if (this.isNew && this.session.userAgent) {
        this.parseUserAgent();
    }
    next();
});


module.exports = mongoose.model('AccessLog', accessLogSchema);
