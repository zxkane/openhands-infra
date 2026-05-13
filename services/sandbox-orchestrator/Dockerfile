FROM public.ecr.aws/docker/library/node:24-alpine AS builder

RUN apk -U upgrade --no-cache

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --ignore-scripts

COPY tsconfig.json ./
COPY src/ ./src/
RUN npx tsc

# Production stage
FROM public.ecr.aws/docker/library/node:24-alpine

RUN apk -U upgrade --no-cache

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

COPY --from=builder /app/dist ./dist

EXPOSE 8081

CMD ["node", "dist/index.js"]
