-- Easebuzz demo schema: payments aggregator scenario
-- transactions / merchants / payouts / kyc_documents
-- INR amounts, UPI/card payment_methods

CREATE TABLE IF NOT EXISTS public.merchants (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    business_type TEXT NOT NULL,
    pan TEXT,
    gstin TEXT,
    onboarded_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.transactions (
    id BIGSERIAL PRIMARY KEY,
    merchant_id BIGINT NOT NULL REFERENCES public.merchants(id),
    amount_inr_paise BIGINT NOT NULL,
    payment_method TEXT NOT NULL CHECK (payment_method IN ('upi', 'card', 'netbanking', 'wallet')),
    status TEXT NOT NULL CHECK (status IN ('initiated', 'success', 'failed', 'refunded')),
    user_id BIGINT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    refund_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_txn_merchant ON public.transactions(merchant_id);
CREATE INDEX IF NOT EXISTS idx_txn_created ON public.transactions(created_at);
CREATE INDEX IF NOT EXISTS idx_txn_user ON public.transactions(user_id);

CREATE TABLE IF NOT EXISTS public.payouts (
    id BIGSERIAL PRIMARY KEY,
    merchant_id BIGINT NOT NULL REFERENCES public.merchants(id),
    amount_inr_paise BIGINT NOT NULL,
    bank_account_last4 TEXT,
    ifsc TEXT,
    status TEXT NOT NULL,
    initiated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.kyc_documents (
    id BIGSERIAL PRIMARY KEY,
    merchant_id BIGINT NOT NULL REFERENCES public.merchants(id),
    doc_type TEXT NOT NULL,
    aadhaar_number TEXT,            -- sensitive
    pan_number TEXT,                -- sensitive
    bank_proof_url TEXT,
    uploaded_at TIMESTAMPTZ DEFAULT NOW()
);

-- Seed merchants (50)
INSERT INTO public.merchants (name, business_type, pan, gstin)
SELECT
    'Merchant ' || g,
    (ARRAY['retail','services','saas','d2c','restaurant'])[1 + (g % 5)],
    'PAN' || lpad(g::text, 7, '0') || 'X',
    lpad(g::text, 2, '0') || 'AAACE' || lpad(g::text, 4, '0') || 'L1Z5'
FROM generate_series(1, 50) g
ON CONFLICT DO NOTHING;

-- Seed transactions (5000) — tail-heavy on amounts
INSERT INTO public.transactions (merchant_id, amount_inr_paise, payment_method, status, user_id, created_at)
SELECT
    1 + (g % 50),
    (10000 + (g * 137) % 5000000)::BIGINT,
    (ARRAY['upi','upi','upi','card','netbanking','wallet'])[1 + (g % 6)],
    (ARRAY['success','success','success','success','failed','refunded'])[1 + (g % 6)],
    1000 + (g % 800),
    NOW() - ((g % 720) || ' minutes')::INTERVAL
FROM generate_series(1, 5000) g;

-- Seed payouts (200)
INSERT INTO public.payouts (merchant_id, amount_inr_paise, bank_account_last4, ifsc, status)
SELECT
    1 + (g % 50),
    (1000000 + (g * 311) % 50000000)::BIGINT,
    lpad((g % 10000)::text, 4, '0'),
    'HDFC000' || lpad((g % 1000)::text, 4, '0'),
    (ARRAY['queued','processed','processed','processed','failed'])[1 + (g % 5)]
FROM generate_series(1, 200) g;

-- Seed KYC docs (50, 1 per merchant)
INSERT INTO public.kyc_documents (merchant_id, doc_type, aadhaar_number, pan_number, bank_proof_url)
SELECT
    g,
    'aadhaar+pan+bank',
    lpad((400000000000 + g)::text, 12, '0'),
    'PAN' || lpad(g::text, 7, '0') || 'X',
    's3://easebuzz-kyc/m' || g || '.pdf'
FROM generate_series(1, 50) g;

ANALYZE;
