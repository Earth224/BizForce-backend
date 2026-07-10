CREATE TABLE IF NOT EXISTS crowdfunding_campaigns (
id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
owner_id uuid NOT NULL,
title text NOT NULL,
description text NOT NULL DEFAULT '',
goal_bfc integer NOT NULL CHECK (goal_bfc > 0),
raised_bfc integer NOT NULL DEFAULT 0 CHECK (raised_bfc >= 0),
media jsonb NOT NULL DEFAULT '[]',
category text,
status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','paused','completed','cancelled')),
created_at timestamptz NOT NULL DEFAULT now(),
updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS campaign_donations (
id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
campaign_id uuid REFERENCES crowdfunding_campaigns(id) ON DELETE SET NULL,
donor_id uuid NOT NULL,
owner_id uuid NOT NULL,
amount_bfc integer NOT NULL CHECK (amount_bfc > 0),
created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE crowdfunding_campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE campaign_donations ENABLE ROW LEVEL SECURITY;

CREATE POLICY campaigns_select ON crowdfunding_campaigns
FOR SELECT USING (status = 'active' OR owner_id = auth.uid());
CREATE POLICY campaigns_insert ON crowdfunding_campaigns
FOR INSERT WITH CHECK (owner_id = auth.uid());
CREATE POLICY campaigns_update ON crowdfunding_campaigns
FOR UPDATE USING (owner_id = auth.uid());
CREATE POLICY campaigns_delete ON crowdfunding_campaigns
FOR DELETE USING (owner_id = auth.uid());

CREATE POLICY donations_select ON campaign_donations
FOR SELECT USING (donor_id = auth.uid() OR owner_id = auth.uid());

CREATE OR REPLACE FUNCTION bfc_donate(p_donor uuid, p_campaign_id uuid, p_amount integer)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
v_owner uuid;
v_status text;
v_title text;
v_new_balance integer;
BEGIN
IF p_amount IS NULL OR p_amount <= 0 THEN
RAISE EXCEPTION 'Donation amount must be a positive integer';
END IF;

SELECT owner_id, status, title
INTO v_owner, v_status, v_title
FROM crowdfunding_campaigns
WHERE id = p_campaign_id
FOR UPDATE;

IF v_owner IS NULL THEN
RAISE EXCEPTION 'Campaign not found';
END IF;

IF v_status <> 'active' THEN
RAISE EXCEPTION 'Campaign is not accepting donations';
END IF;

IF v_owner = p_donor THEN
RAISE EXCEPTION 'You cannot donate to your own campaign';
END IF;

v_new_balance := bfc_transfer(p_donor, v_owner, p_amount, 'Donation: ' || v_title);

INSERT INTO campaign_donations (campaign_id, donor_id, owner_id, amount_bfc)
VALUES (p_campaign_id, p_donor, v_owner, p_amount);

UPDATE crowdfunding_campaigns
SET raised_bfc = raised_bfc + p_amount,
updated_at = now()
WHERE id = p_campaign_id;

RETURN v_new_balance;
END;
$$;
