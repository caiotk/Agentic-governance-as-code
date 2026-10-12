# Governance control plane (reference deployment)
FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=optional && npm cache clean --force
COPY tsconfig.json ./
COPY src ./src
COPY policy ./policy
COPY agents ./agents
COPY docs ./docs
ENV HOST=0.0.0.0 PORT=8787 NODE_ENV=production
# ADMIN_KEY (24+ chars) and GOV_SIGNING_SECRET must be supplied at runtime.
USER node
EXPOSE 8787
CMD ["npx", "tsx", "src/server.ts"]
