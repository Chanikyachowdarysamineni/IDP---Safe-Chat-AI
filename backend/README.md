# Backend (Emotion Shield)

This backend is a small Express app intended to replace the previous Supabase usage. It uses MongoDB (Mongoose) and exposes simple REST endpoints under `/api/*`.

Endpoints summary
- `POST /api/auth/signup` - body: { email, password, username }
- `POST /api/auth/signin` - body: { email, password }
- `GET /api/auth/session` - requires Bearer token
- `GET /api/messages` - list messages
- `POST /api/messages` - create message (requires Bearer token)
- `GET /api/messages/flagged` - flagged messages
- `GET /api/profiles/:id` - profile for user
- `PUT /api/profiles/:id` - update profile (protected)
- `POST /api/moderation_actions` - add moderation action (protected)

Additional ML / data collection endpoints
- `POST /api/annotations` - submit an annotation/feedback for a message (protected). Body: { message_id, content, labels }
- `GET /api/annotations` - list recent annotations
- `POST /api/analyze` - server-side analysis (accepts { text }). If the backend is configured with HF_API_TOKEN and HF_MODEL it will use the Hugging Face Inference API; otherwise it falls back to a lightweight heuristic.
- `GET /api/export-dataset` - export messages + annotations as JSON (admin only)

Quick start

1. cd backend
2. npm install
3. Copy `.env.example` to `.env` and set `MONGO_URI` and `JWT_SECRET`
4. npm run dev

Notes
- This is a minimal reference backend to get you started. It uses JWTs (signed by `JWT_SECRET`) for authentication.
- For production use, secure the JWT secret, enable HTTPS, and add proper validation and rate limits.

Server-side ML notes
- To enable improved server-side analysis using Hugging Face Inference API, set `HF_API_TOKEN` and optionally `HF_MODEL` in your `.env` (see `.env.example`).
- Use `/api/export-dataset` to download collected messages and user annotations for offline training.
- Consider adding periodic training scripts or CI pipelines to consume exported datasets and produce a model endpoint (this repo includes only dataset collection & a simple HF proxy).
