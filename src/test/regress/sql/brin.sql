CREATE TABLE brintest (byteacol bytea,
	charcol "char",
	namecol name,
	int8col bigint,
	int2col smallint,
	int4col integer,
	textcol text,
	oidcol oid,
	tidcol tid,
	float4col real,
	float8col double precision,
	macaddrcol macaddr,
	inetcol inet,
	cidrcol cidr,
	bpcharcol character,
	datecol date,
	timecol time without time zone,
	timestampcol timestamp without time zone,
	timestamptzcol timestamp with time zone,
	intervalcol interval,
	timetzcol time with time zone,
	bitcol bit(10),
	varbitcol bit varying(16),
	numericcol numeric,
	uuidcol uuid,
	int4rangecol int4range,
	lsncol pg_lsn,
	boxcol box
) WITH (fillfactor=10, autovacuum_enabled=off);

INSERT INTO brintest SELECT
	repeat(stringu1, 8)::bytea,
	substr(stringu1, 1, 1)::"char",
	stringu1::name, 142857 * tenthous,
	thousand,
	twothousand,
	repeat(stringu1, 8),
	unique1::oid,
	format('(%s,%s)', tenthous, twenty)::tid,
	(four + 1.0)/(hundred+1),
	odd::float8 / (tenthous + 1),
	format('%s:00:%s:00:%s:00', to_hex(odd), to_hex(even), to_hex(hundred))::macaddr,
	inet '10.2.3.4/24' + tenthous,
	cidr '10.2.3/24' + tenthous,
	substr(stringu1, 1, 1)::bpchar,
	date '1995-08-15' + tenthous,
	time '01:20:30' + thousand * interval '18.5 second',
	timestamp '1942-07-23 03:05:09' + tenthous * interval '36.38 hours',
	timestamptz '1972-10-10 03:00' + thousand * interval '1 hour',
	justify_days(justify_hours(tenthous * interval '12 minutes')),
	timetz '01:30:20+02' + hundred * interval '15 seconds',
	thousand::bit(10),
	tenthous::bit(16)::varbit,
	tenthous::numeric(36,30) * fivethous * even / (hundred + 1),
	format('%s%s-%s-%s-%s-%s%s%s', to_char(tenthous, 'FM0000'), to_char(tenthous, 'FM0000'), to_char(tenthous, 'FM0000'), to_char(tenthous, 'FM0000'), to_char(tenthous, 'FM0000'), to_char(tenthous, 'FM0000'), to_char(tenthous, 'FM0000'), to_char(tenthous, 'FM0000'))::uuid,
	int4range(thousand, twothousand),
	format('%s/%s%s', odd, even, tenthous)::pg_lsn,
	box(point(odd, even), point(thousand, twothousand))
FROM tenk1 LIMIT 100;

-- throw in some NULL's and different values
INSERT INTO brintest (inetcol, cidrcol, int4rangecol) SELECT
	inet 'fe80::6e40:8ff:fea9:8c46' + tenthous,
	cidr 'fe80::6e40:8ff:fea9:8c46' + tenthous,
	'empty'::int4range
FROM tenk1 LIMIT 25;

CREATE INDEX brinidx ON brintest USING brin (
	byteacol,
	charcol,
	namecol,
	int8col,
	int2col,
	int4col,
	textcol,
	oidcol,
	tidcol,
	float4col,
	float8col,
	macaddrcol,
	inetcol inet_inclusion_ops,
	inetcol inet_minmax_ops,
	bpcharcol,
	datecol,
	timecol,
	timestampcol,
	timestamptzcol,
	intervalcol,
	timetzcol,
	bitcol,
	varbitcol,
	numericcol,
	uuidcol,
	int4rangecol,
	lsncol,
	boxcol
) with (pages_per_range = 1);

CREATE TABLE brinopers (colname name, typ text, op text[], value text[],
	check (cardinality(op) = cardinality(value)));

INSERT INTO brinopers VALUES
	('byteacol', 'bytea', '{>, >=, =, <=, <}', '{AAAAAA, AAAAAA, BNAAAABNAAAABNAAAABNAAAABNAAAABNAAAABNAAAABNAAAA, ZZZZZZ, ZZZZZZ}'),
	('charcol', 'char', '{>, >=, =, <=, <}', '{A, A, M, Z, Z}'),
	('namecol', 'name', '{>, >=, =, <=, <}', '{AAAAAA, AAAAAA, MAAAAA, ZZAAAA, ZZAAAA}'),
	('int2col', 'int2', '{>, >=, =, <=, <}', '{0, 0, 800, 999, 999}'),
	('int2col', 'int4', '{>, >=, =, <=, <}', '{0, 0, 800, 999, 1999}'),
	('int2col', 'int8', '{>, >=, =, <=, <}', '{0, 0, 800, 999, 1428427143}'),
	('int4col', 'int2', '{>, >=, =, <=, <}', '{0, 0, 800, 1999, 1999}'),
	('int4col', 'int4', '{>, >=, =, <=, <}', '{0, 0, 800, 1999, 1999}'),
	('int4col', 'int8', '{>, >=, =, <=, <}', '{0, 0, 800, 1999, 1428427143}'),
	('int8col', 'int2', '{>, >=}', '{0, 0}'),
	('int8col', 'int4', '{>, >=}', '{0, 0}'),
	('int8col', 'int8', '{>, >=, =, <=, <}', '{0, 0, 1257141600, 1428427143, 1428427143}'),
	('textcol', 'text', '{>, >=, =, <=, <}', '{AAAAAA, AAAAAA, BNAAAABNAAAABNAAAABNAAAABNAAAABNAAAABNAAAABNAAAA, ZZAAAA, ZZAAAA}'),
	('oidcol', 'oid', '{>, >=, =, <=, <}', '{0, 0, 8800, 9999, 9999}'),
	('tidcol', 'tid', '{>, >=, =, <=, <}', '{"(0,0)", "(0,0)", "(8800,0)", "(9999,19)", "(9999,19)"}'),
	('float4col', 'float4', '{>, >=, =, <=, <}', '{0.0103093, 0.0103093, 1, 1, 1}'),
	('float4col', 'float8', '{>, >=, =, <=, <}', '{0.0103093, 0.0103093, 1, 1, 1}'),
	('float8col', 'float4', '{>, >=, =, <=, <}', '{0, 0, 0, 1.98, 1.98}'),
	('float8col', 'float8', '{>, >=, =, <=, <}', '{0, 0, 0, 1.98, 1.98}'),
	('macaddrcol', 'macaddr', '{>, >=, =, <=, <}', '{00:00:01:00:00:00, 00:00:01:00:00:00, 2c:00:2d:00:16:00, ff:fe:00:00:00:00, ff:fe:00:00:00:00}'),
	('inetcol', 'inet', '{&&, =, <, <=, >, >=, >>=, >>, <<=, <<}', '{10/8, 10.2.14.231/24, 255.255.255.255, 255.255.255.255, 0.0.0.0, 0.0.0.0, 10.2.14.231/24, 10.2.14.231/25, 10.2.14.231/8, 0/0}'),
	('inetcol', 'inet', '{&&, >>=, <<=, =}', '{fe80::6e40:8ff:fea9:a673/32, fe80::6e40:8ff:fea9:8c46, fe80::6e40:8ff:fea9:a673/32, fe80::6e40:8ff:fea9:8c46}'),
	('inetcol', 'cidr', '{&&, <, <=, >, >=, >>=, >>, <<=, <<}', '{10/8, 255.255.255.255, 255.255.255.255, 0.0.0.0, 0.0.0.0, 10.2.14/24, 10.2.14/25, 10/8, 0/0}'),
	('inetcol', 'cidr', '{&&, >>=, <<=, =}', '{fe80::/32, fe80::6e40:8ff:fea9:8c46, fe80::/32, fe80::6e40:8ff:fea9:8c46}'),
	('cidrcol', 'inet', '{&&, =, <, <=, >, >=, >>=, >>, <<=, <<}', '{10/8, 10.2.14/24, 255.255.255.255, 255.255.255.255, 0.0.0.0, 0.0.0.0, 10.2.14.231/24, 10.2.14.231/25, 10.2.14.231/8, 0/0}'),
	('cidrcol', 'inet', '{&&, >>=, <<=, =}', '{fe80::6e40:8ff:fea9:a673/32, fe80::6e40:8ff:fea9:8c46, fe80::6e40:8ff:fea9:a673/32, fe80::6e40:8ff:fea9:8c46}'),
	('cidrcol', 'cidr', '{&&, =, <, <=, >, >=, >>=, >>, <<=, <<}', '{10/8, 10.2.14/24, 255.255.255.255, 255.255.255.255, 0.0.0.0, 0.0.0.0, 10.2.14/24, 10.2.14/25, 10/8, 0/0}'),
	('cidrcol', 'cidr', '{&&, >>=, <<=, =}', '{fe80::/32, fe80::6e40:8ff:fea9:8c46, fe80::/32, fe80::6e40:8ff:fea9:8c46}'),
	('bpcharcol', 'bpchar', '{>, >=, =, <=, <}', '{A, A, W, Z, Z}'),
	('datecol', 'date', '{>, >=, =, <=, <}', '{1995-08-15, 1995-08-15, 2009-12-01, 2022-12-30, 2022-12-30}'),
	('timecol', 'time', '{>, >=, =, <=, <}', '{01:20:30, 01:20:30, 02:28:57, 06:28:31.5, 06:28:31.5}'),
	('timestampcol', 'timestamp', '{>, >=, =, <=, <}', '{1942-07-23 03:05:09, 1942-07-23 03:05:09, 1964-03-24 19:26:45, 1984-01-20 22:42:21, 1984-01-20 22:42:21}'),
	('timestampcol', 'timestamptz', '{>, >=, =, <=, <}', '{1942-07-23 03:05:09, 1942-07-23 03:05:09, 1964-03-24 19:26:45, 1984-01-20 22:42:21, 1984-01-20 22:42:21}'),
	('timestampcol', 'timestamptz', '{>, >=, =, <=, <}', '{1942-07-23 03:05:09, 1942-07-23 03:05:09, 1964-03-24 19:26:45, 1984-01-20 22:42:21, 1984-01-20 22:42:21}'),
	('timestamptzcol', 'timestamptz', '{>, >=, =, <=, <}', '{1972-10-10 03:00:00-04, 1972-10-10 03:00:00-04, 1972-10-19 09:00:00-07, 1972-11-20 19:00:00-03, 1972-11-20 19:00:00-03}'),
	('intervalcol', 'interval', '{>, >=, =, <=, <}', '{00:00:00, 00:00:00, 1 mons 13 days 12:24, 2 mons 23 days 07:48:00, 1 year}'),
	('timetzcol', 'timetz', '{>, >=, =, <=, <}', '{01:30:20+02, 01:30:20+02, 01:35:50+02, 23:55:05+02, 23:55:05+02}'),
	('bitcol', 'bit(10)', '{>, >=, =, <=, <}', '{0000000010, 0000000010, 0011011110, 1111111000, 1111111000}'),
	('varbitcol', 'varbit(16)', '{>, >=, =, <=, <}', '{0000000000000100, 0000000000000100, 0001010001100110, 1111111111111000, 1111111111111000}'),
	('numericcol', 'numeric', '{>, >=, =, <=, <}', '{0.00, 0.01, 2268164.347826086956521739130434782609, 99470151.9, 99470151.9}'),
	('uuidcol', 'uuid', '{>, >=, =, <=, <}', '{00040004-0004-0004-0004-000400040004, 00040004-0004-0004-0004-000400040004, 52225222-5222-5222-5222-522252225222, 99989998-9998-9998-9998-999899989998, 99989998-9998-9998-9998-999899989998}'),
	('int4rangecol', 'int4range', '{<<, &<, &&, &>, >>, @>, <@, =, <, <=, >, >=}', '{"[10000,)","[10000,)","(,]","[3,4)","[36,44)","(1500,1501]","[3,4)","[222,1222)","[36,44)","[43,1043)","[367,4466)","[519,)"}'),
	('int4rangecol', 'int4range', '{@>, <@, =, <=, >, >=}', '{empty, empty, empty, empty, empty, empty}'),
	('int4rangecol', 'int4', '{@>}', '{1500}'),
	('lsncol', 'pg_lsn', '{>, >=, =, <=, <, IS, IS NOT}', '{0/1200, 0/1200, 44/455222, 198/1999799, 198/1999799, NULL, NULL}'),
	('boxcol', 'point', '{@>}', '{"(500,43)"}'),
	('boxcol', 'box', '{<<, &<, &&, &>, >>, <<|, &<|, |&>, |>>, @>, <@, ~=}', '{"((1000,2000),(3000,4000))","((1,2),(3000,4000))","((1,2),(3000,4000))","((1,2),(3000,4000))","((1,2),(3,4))","((1000,2000),(3000,4000))","((1,2000),(3,4000))","((1000,2),(3000,4))","((1,2),(3,4))","((1,2),(300,400))","((1,2),(3000,4000))","((222,1222),(44,45))"}');

DO $x$
DECLARE
	r record;
	r2 record;
	cond text;
	count int;
	mismatch bool;
BEGIN
	FOR r IN SELECT colname, oper, typ, value[ordinality] FROM brinopers, unnest(op) WITH ORDINALITY AS oper LOOP
		mismatch := false;

		-- prepare the condition
		IF r.value IS NULL THEN
			cond := format('%I %s %L', r.colname, r.oper, r.value);
		ELSE
			cond := format('%I %s %L::%s', r.colname, r.oper, r.value, r.typ);
		END IF;

		-- run the query using the brin index
		CREATE TEMP TABLE brin_result (cid tid);
		SET enable_seqscan = 0;
		SET enable_bitmapscan = 1;
		EXECUTE format($y$INSERT INTO brin_result SELECT ctid FROM brintest WHERE %s $y$, cond);

		-- run the query using a seqscan
		CREATE TEMP TABLE brin_result_ss (cid tid);
		SET enable_seqscan = 1;
		SET enable_bitmapscan = 0;
		EXECUTE format($y$INSERT INTO brin_result_ss SELECT ctid FROM brintest WHERE %s $y$, cond);

		-- make sure both return the same results
		PERFORM * FROM brin_result EXCEPT ALL SELECT * FROM brin_result_ss;
		GET DIAGNOSTICS count = ROW_COUNT;
		IF count <> 0 THEN
			mismatch = true;
		END IF;
		PERFORM * FROM brin_result_ss EXCEPT ALL SELECT * FROM brin_result;
		GET DIAGNOSTICS count = ROW_COUNT;
		IF count <> 0 THEN
			mismatch = true;
		END IF;

		-- report the results of each scan to make the differences obvious
		IF mismatch THEN
			RAISE WARNING 'something not right in %: count %', r, count;
			SET enable_seqscan = 1;
			SET enable_bitmapscan = 0;
			FOR r2 IN EXECUTE 'SELECT ' || r.colname || ' FROM brintest WHERE ' || cond LOOP
				RAISE NOTICE 'seqscan: %', r2;
			END LOOP;

			SET enable_seqscan = 0;
			SET enable_bitmapscan = 1;
			FOR r2 IN EXECUTE 'SELECT ' || r.colname || ' FROM brintest WHERE ' || cond LOOP
				RAISE NOTICE 'bitmapscan: %', r2;
			END LOOP;
		END IF;

		-- make sure it was a sensible test case
		SELECT count(*) INTO count FROM brin_result;
		IF count = 0 THEN RAISE WARNING 'no results for %', r; END IF;

		-- drop the temporary tables
		DROP TABLE brin_result;
		DROP TABLE brin_result_ss;
	END LOOP;
END;
$x$;

INSERT INTO brintest SELECT
	repeat(stringu1, 42)::bytea,
	substr(stringu1, 1, 1)::"char",
	stringu1::name, 142857 * tenthous,
	thousand,
	twothousand,
	repeat(stringu1, 42),
	unique1::oid,
	format('(%s,%s)', tenthous, twenty)::tid,
	(four + 1.0)/(hundred+1),
	odd::float8 / (tenthous + 1),
	format('%s:00:%s:00:%s:00', to_hex(odd), to_hex(even), to_hex(hundred))::macaddr,
	inet '10.2.3.4' + tenthous,
	cidr '10.2.3/24' + tenthous,
	substr(stringu1, 1, 1)::bpchar,
	date '1995-08-15' + tenthous,
	time '01:20:30' + thousand * interval '18.5 second',
	timestamp '1942-07-23 03:05:09' + tenthous * interval '36.38 hours',
	timestamptz '1972-10-10 03:00' + thousand * interval '1 hour',
	justify_days(justify_hours(tenthous * interval '12 minutes')),
	timetz '01:30:20' + hundred * interval '15 seconds',
	thousand::bit(10),
	tenthous::bit(16)::varbit,
	tenthous::numeric(36,30) * fivethous * even / (hundred + 1),
	format('%s%s-%s-%s-%s-%s%s%s', to_char(tenthous, 'FM0000'), to_char(tenthous, 'FM0000'), to_char(tenthous, 'FM0000'), to_char(tenthous, 'FM0000'), to_char(tenthous, 'FM0000'), to_char(tenthous, 'FM0000'), to_char(tenthous, 'FM0000'), to_char(tenthous, 'FM0000'))::uuid,
	int4range(thousand, twothousand),
	format('%s/%s%s', odd, even, tenthous)::pg_lsn,
	box(point(odd, even), point(thousand, twothousand))
FROM tenk1 LIMIT 5 OFFSET 5;

SELECT brin_summarize_new_values('brinidx'::regclass);

UPDATE brintest SET int8col = int8col * int4col;
UPDATE brintest SET textcol = '' WHERE textcol IS NOT NULL;
