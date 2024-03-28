import { createLogger, format, transports } from 'winston';

export default createLogger({
    level: 'debug',
    format: format.combine(format.cli(), format.timestamp()),//format.combine(format.label({ label: 'SDS-D' }), format.timestamp(), format.printf((level, message, label, timestamp) => {
    //    return `${timestamp} ${label} ${level}: ${message}`;
    //})),
    transports: [
        new transports.Console()
    ]
});