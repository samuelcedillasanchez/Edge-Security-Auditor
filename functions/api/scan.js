export async function onRequest(context) {
  if (context.request.method === "OPTIONS") {
    return new Response(null, {
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
      },
    });
  }

  try {
    const body = await context.request.json();
    const rawUrl = (body.url || "").trim();
    if (!rawUrl) throw new Error("Missing URL parameter");

    const domain = rawUrl
      .replace(/^(?:https?:\/\/)?(?:www\.)?/i, "")
      .split('/')
      .split('?')
      .toLowerCase();

    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) {
      throw new Error("Invalid domain scope: " + domain);
    }

    let h = {};
    let httpStatus = null;
    let finalUrl = `https://${domain}`;
    try {
      const httpRes = await fetch(`https://${domain}`, {
        method: 'HEAD',
        redirect: 'follow',
        headers: {
          'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
          'Accept': 'text/html,application/xhtml+xml,*/*;q=0.9',
          'Accept-Language': 'en-US,en;q=0.5',
        },
        signal: AbortSignal.timeout(8000),
      });
      h = Object.fromEntries(httpRes.headers.entries());
      httpStatus = httpRes.status;
      finalUrl = httpRes.url || finalUrl;
    } catch (e) {
      try {
        const httpRes2 = await fetch(`https://${domain}`, {
          method: 'GET',
          redirect: 'follow',
          headers: {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
          },
          signal: AbortSignal.timeout(8000),
        });
        h = Object.fromEntries(httpRes2.headers.entries());
        httpStatus = httpRes2.status;
      } catch (e2) {
      }
    }

    let hasSPF = false, hasDMARC = false, spfRecord = null, dmarcRecord = null;
    let mxRecords = [], aRecords = [], nsRecords = [];

    const dnsBase = 'https://cloudflare-dns.com/dns-query';
    const dnsHeaders = { 'accept': 'application/dns-json' };

    const [txtRes, dmarcRes, mxRes, aRes, nsRes] = await Promise.allSettled([
      fetch(`${dnsBase}?name=${domain}&type=TXT`, { headers: dnsHeaders }),
      fetch(`${dnsBase}?name=_dmarc.${domain}&type=TXT`, { headers: dnsHeaders }),
      fetch(`${dnsBase}?name=${domain}&type=MX`, { headers: dnsHeaders }),
      fetch(`${dnsBase}?name=${domain}&type=A`, { headers: dnsHeaders }),
      fetch(`${dnsBase}?name=${domain}&type=NS`, { headers: dnsHeaders }),
    ]);

    if (txtRes.status === 'fulfilled') {
      const d = await txtRes.value.json();
      const txt = JSON.stringify(d.Answer || []);
      hasSPF = txt.toLowerCase().includes("v=spf1");
      if (hasSPF) {
        const spfEntry = (d.Answer || []).find(r => r.data?.toLowerCase().includes('v=spf1'));
        spfRecord = spfEntry?.data || null;
      }
    }

    if (dmarcRes.status === 'fulfilled') {
      const d = await dmarcRes.value.json();
      const txt = JSON.stringify(d.Answer || []);
      hasDMARC = txt.toLowerCase().includes("v=dmarc1");
      if (hasDMARC) {
        const dmarcEntry = (d.Answer || []).find(r => r.data?.toLowerCase().includes('v=dmarc1'));
        dmarcRecord = dmarcEntry?.data || null;
      }
    }

    if (mxRes.status === 'fulfilled') {
      const d = await mxRes.value.json();
      mxRecords = (d.Answer || []).map(r => r.data).filter(Boolean).slice(0, 3);
    }

    if (aRes.status === 'fulfilled') {
      const d = await aRes.value.json();
      aRecords = (d.Answer || []).map(r => r.data).filter(Boolean).slice(0, 2);
    }

    if (nsRes.status === 'fulfilled') {
      const d = await nsRes.value.json();
      nsRecords = (d.Answer || []).map(r => r.data).filter(Boolean).slice(0, 2);
    }

    let ipInfo = null;
    if (aRecords.length > 0) {
      try {
        const ipRes = await fetch(`https://ipapi.co/${aRecords}/json/`, {
          signal: AbortSignal.timeout(4000),
        });
        if (ipRes.ok) ipInfo = await ipRes.json();
      } catch (e) {}
    }

    let sslGrade = null, sslProtocol = null, sslExpiry = null;
    try {
      const sslRes = await fetch(
        `https://api.ssllabs.com/api/v3/analyze?host=${domain}&fromCache=on&maxAge=48&all=done`,
        { signal: AbortSignal.timeout(6000) }
      );
      if (sslRes.ok) {
        const sslData = await sslRes.json();
        if (sslData.status === 'READY' && sslData.endpoints?.length > 0) {
          sslGrade = sslData.endpoints.grade || null;
          const protocols = sslData.endpoints.details?.protocols || [];
          const best = protocols.sort((a, b) => b.version.localeCompare(a.version));
          sslProtocol = best ? `${best.name} ${best.version}` : null;
          const cert = sslData.endpoints.details?.cert;
          if (cert?.notAfter) {
            const expiry = new Date(cert.notAfter);
            sslExpiry = expiry.toLocaleDateString('en-US');
          }
        }
      }
    } catch (e) {}

    let hasRobots = false;
    try {
      const robotsRes = await fetch(`https://${domain}/robots.txt`, {
        signal: AbortSignal.timeout(4000),
      });
      hasRobots = robotsRes.ok && robotsRes.status === 200;
    } catch (e) {}

    let hasSecurityTxt = false;
    try {
      const secRes = await fetch(`https://${domain}/.well-known/security.txt`, {
        signal: AbortSignal.timeout(4000),
      });
      hasSecurityTxt = secRes.ok && secRes.status === 200;
    } catch (e) {}

    let score = 100;
    const deductions = [];

    if (!h['strict-transport-security']) {
      score -= 20; deductions.push('Missing HSTS (-20)');
    }
    if (!h['content-security-policy']) {
      score -= 20; deductions.push('Missing CSP (-20)');
    }
    if (!h['x-frame-options'] && !h['content-security-policy']?.includes('frame-ancestors')) {
      score -= 15; deductions.push('Missing X-Frame-Options (-15)');
    }
    if (!h['x-content-type-options']) {
      score -= 10; deductions.push('Missing X-Content-Type-Options (-10)');
    }
    if (!h['referrer-policy']) {
      score -= 5; deductions.push('Missing Referrer-Policy (-5)');
    }
    if (!h['permissions-policy'] && !h['feature-policy']) {
      score -= 5; deductions.push('Missing Permissions-Policy (-5)');
    }
    if (!hasSPF)   { score -= 10; deductions.push('Missing SPF (-10)'); }
    if (!hasDMARC) { score -= 10; deductions.push('Missing DMARC (-10)'); }
    if (httpStatus === null) { score -= 5; }

    if (score < 0) score = 0;

    let grade = "A+";
    if (score < 95) grade = "A";
    if (score < 80) grade = "B";
    if (score < 60) grade = "C";
    if (score < 40) grade = "D";
    if (score < 20) grade = "F";

    return new Response(JSON.stringify({
      domain,
      score,
      grade,
      httpStatus,
      headers: {
        hsts:          h['strict-transport-security']
                         ? `✅ ${h['strict-transport-security'].substring(0, 40)}` : '❌ NOT CONFIGURED',
        csp:           h['content-security-policy']
                         ? '✅ ACTIVE' : '⚠️ MISSING CSP',
        xframe:        (h['x-frame-options'] || h['content-security-policy']?.includes('frame-ancestors'))
                         ? `✅ ${h['x-frame-options'] || 'via CSP'}` : '⚠️ VULNERABLE',
        xcontent:      h['x-content-type-options']
                         ? `✅ ${h['x-content-type-options']}` : '⚠️ NOT CONFIGURED',
        referrer:      h['referrer-policy']
                         ? `✅ ${h['referrer-policy']}` : '⚠️ NOT CONFIGURED',
        permissions:   (h['permissions-policy'] || h['feature-policy'])
                         ? '✅ ACTIVE' : '⚠️ NOT CONFIGURED',
        server:        h['server'] || 'Not disclosed',
        poweredBy:     h['x-powered-by'] || 'Not disclosed',
      },
      dns: {
        spf:      hasSPF ? `✅ ${spfRecord?.substring(0, 50) || 'ACTIVE'}` : '❌ NOT DETECTED',
        dmarc:    hasDMARC ? `✅ ${dmarcRecord?.substring(0, 50) || 'ACTIVE'}` : '❌ NOT DETECTED',
        mx:       mxRecords.length > 0 ? `✅ ${mxRecords}` : '⚠️ MISSING MX',
        ns:       nsRecords.join(', ') || 'Not detected',
        ip:       aRecords || 'Unresolved',
      },
      ssl: {
        grade:    sslGrade || (h['strict-transport-security'] ? 'HTTPS ✅' : '❓'),
        protocol: sslProtocol || (httpStatus ? 'TLS (unverified)' : 'No response'),
        expiry:   sslExpiry || 'Not available',
      },
      ip: ipInfo ? {
        city:    ipInfo.city,
        country: ipInfo.country_name,
        org:     ipInfo.org,
        region:  ipInfo.region,
      } : null,
      extras: {
        robots:      hasRobots,
        securityTxt: hasSecurityTxt,
      },
      deductions,
    }), {
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
      }
    });

  } catch (error) {
    return new Response(JSON.stringify({
      error: "Scan execution failure",
      details: error.message,
    }), {
      status: 500,
      headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
    });
  }
}
