FROM node:24 AS deps

WORKDIR /app

COPY package*.json ./

RUN npm ci --include=dev

FROM node:24 AS builder

WORKDIR /app

ARG NEXT_PUBLIC_API_URL

ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}

COPY --from=deps /app/node_modules ./node_modules

COPY . .

RUN npm run build && npm prune --omit=dev

FROM node:24 AS runner

WORKDIR /app

ENV NODE_ENV=production

ARG NEXT_PUBLIC_API_URL

ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}

COPY --from=builder /app/.next ./.next

COPY --from=builder /app/public ./public

COPY --from=builder /app/package.json ./package.json

COPY --from=builder /app/package-lock.json ./package-lock.json

COPY --from=builder /app/node_modules ./node_modules

EXPOSE 3000
CMD ["npm", "run", "start"]
