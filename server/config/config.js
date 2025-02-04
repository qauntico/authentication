const config = {
    jwtAccessSecret: process.env.JWT_ACCESS_SECRET || 'your-access-secret-key',
    jwtRefreshSecret: process.env.JWT_REFRESH_SECRET || 'your-refresh-secret-key',
    accessTokenExpiry: '15m',
    refreshTokenExpiry: '7d',
    cookieMaxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  };
  
 export default config;