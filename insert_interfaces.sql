INSERT INTO interfaces (id, exporter, snmp_index)
SELECT 
    sipHash64(exporter, if) AS id,
    CAST(toIPv4(exporter) AS UInt64) AS exporter,
    CAST(if AS UInt64) AS snmp_index
FROM (
    SELECT exporter, input AS if FROM netflow.flows_daily_mv GROUP BY exporter, input
    UNION DISTINCT
    SELECT exporter, output AS if FROM netflow.flows_daily_mv GROUP BY exporter, output
) AS sub
ORDER BY if ASC;
