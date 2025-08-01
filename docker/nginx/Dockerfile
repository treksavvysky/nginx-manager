# NGINX Configuration for Docker Container
FROM nginx:alpine

# Copy the basic nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Create directories for configurations
RUN mkdir -p /etc/nginx/conf.d /var/log/nginx

# Set proper permissions
RUN chown -R nginx:nginx /etc/nginx /var/log/nginx

# Expose ports
EXPOSE 80 443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/health || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
