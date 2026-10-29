(function(){
  var CONFIG={email:"editorvideo252@gmail.com"};
  var $=function(id){return document.getElementById(id);};
  var last=null;

  var PROVIDERS=[
    {id:"google",name:"Google Workspace",mx:/(google\.com|googlemail\.com)\.?$/i,spf:"include:_spf.google.com",spfRe:/_spf\.google\.com/i,dkim:["google"],
     dkimHow:"Google Admin console → Apps → Google Workspace → Gmail → Authenticate email → Generate new record. Add the TXT record it gives you at google._domainkey, wait an hour, then click Start authentication."},
    {id:"microsoft",name:"Microsoft 365",mx:/mail\.protection\.outlook\.com\.?$/i,spf:"include:spf.protection.outlook.com",spfRe:/spf\.protection\.outlook\.com/i,dkim:["selector1","selector2"],
     dkimHow:"Microsoft Defender portal → Email & collaboration → Policies → Email authentication settings → DKIM. Pick your domain, add the two CNAME records it shows (selector1 and selector2), then switch DKIM on."},
    {id:"zoho",name:"Zoho Mail",mx:/zoho\.(com|in|eu|com\.au|jp)\.?$/i,spf:"include:zoho.com",spfRe:/zoho\.(com|in|eu|com\.au|jp)/i,dkim:["zmail","zoho","default"],
     dkimHow:"Zoho Mail Admin Console → Domains → your domain → Email configuration → DKIM → Add selector. Copy the TXT record into your DNS, then click Verify. (India accounts use include:zoho.in for SPF.)"},
    {id:"godaddy",name:"GoDaddy / Microsoft email",mx:/secureserver\.net\.?$/i,spf:"include:secureserver.net",spfRe:/secureserver\.net/i,dkim:["default","selector1","selector2"],
     dkimHow:"Ask GoDaddy support to switch on DKIM for your mailbox plan, or check Email & Office settings. Most GoDaddy plans now run on Microsoft 365, which uses selector1 and selector2."},
    {id:"titan",name:"Titan Mail",mx:/titan\.email\.?$/i,spf:"include:spf.titan.email",spfRe:/spf\.titan\.email/i,dkim:["titan1","titan","default"],
     dkimHow:"Titan admin panel (or your host's Titan page) → Domain → DNS records. Copy the DKIM TXT record it lists into your DNS."},
    {id:"hostinger",name:"Hostinger Email",mx:/hostinger\.(com|in|io)\.?$/i,spf:"include:_spf.mail.hostinger.com",spfRe:/hostinger/i,dkim:["hostingermail1","hostingermail2","hostingermail3"],
     dkimHow:"Hostinger hPanel → Emails → your domain → DNS settings. Hostinger shows three DKIM CNAME records (hostingermail1, 2 and 3). Add any that are missing."},
    {id:"proton",name:"Proton Mail",mx:/protonmail\.ch\.?$/i,spf:"include:_spf.protonmail.ch",spfRe:/protonmail\.ch/i,dkim:["protonmail","protonmail2","protonmail3"],
     dkimHow:"Proton Mail → Settings → Domain names → Review → DKIM. Add the three CNAME records it shows."},
    {id:"fastmail",name:"Fastmail",mx:/messagingengine\.com\.?$/i,spf:"include:spf.messagingengine.com",spfRe:/messagingengine\.com/i,dkim:["fm1","fm2","fm3"],
     dkimHow:"Fastmail → Settings → Domains → your domain → DNS records. Add the three DKIM CNAME records (fm1, fm2, fm3)."},
    {id:"yahoo",name:"Yahoo Business Email",mx:/yahoodns\.net\.?$/i,spf:"",spfRe:/yahoo/i,dkim:["s1024","s2048","default"],
     dkimHow:"Check your Yahoo Business Email DNS page for the DKIM record and add it to your DNS."}
  ];
  var GATEWAYS=[{re:/mimecast/i,name:"Mimecast"},{re:/pphosted\.com/i,name:"Proofpoint"},{re:/barracudanetworks\.com/i,name:"Barracuda"},{re:/iphmx\.com/i,name:"Cisco Secure Email"}];
  var SENDERS=[
    {name:"SendGrid",inc:"include:sendgrid.net",re:/sendgrid\.net/i},
    {name:"Brevo",inc:"include:spf.brevo.com",re:/(brevo|sendinblue)\.com/i},
    {name:"Amazon SES",inc:"include:amazonses.com",re:/amazonses\.com/i},
    {name:"Mailgun",inc:"include:mailgun.org",re:/mailgun\.org/i},
    {name:"Postmark",inc:"include:spf.mtasv.net",re:/mtasv\.net/i},
    {name:"Zendesk",inc:"include:mail.zendesk.com",re:/zendesk\.com/i},
    {name:"Freshdesk",inc:"include:email.freshdesk.com",re:/freshdesk\.com/i},
    {name:"Mailchimp / Mandrill",inc:"include:servers.mcsv.net",re:/mcsv\.net|mandrillapp/i}
  ];
  var COMMON_SELECTORS=["default","dkim","mail","k1","k2","s1","s2","selector1","selector2","google","zmail","mandrill","smtp","sig1","mxvault","everlytickey1","pm","hs1","hs2"];

  function esc(s){return String(s).replace(/[&<>"']/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c];});}
  function cleanDomain(v){
    v=(v||"").trim().toLowerCase();
    if(v.indexOf("@")>-1) v=v.split("@").pop();
    v=v.replace(/^[a-z]+:\/\//,"").replace(/^www\./,"").split(/[\/?#:\s]/)[0].replace(/\.$/,"");
    return /^(?=.{3,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$/.test(v)?v:"";
  }
  function txtJoin(d){ // DNS JSON gives "part1" "part2"
    var m=String(d).match(/"((?:[^"\\]|\\.)*)"/g);
    if(!m) return String(d);
    return m.map(function(x){return x.slice(1,-1).replace(/\\"/g,'"');}).join("");
  }
  function withTimeout(p,ms){return Promise.race([p,new Promise(function(_,r){setTimeout(function(){r(new Error("timeout"));},ms);})]);}
  var cache={};
  function q(name,type){
    var key=name+"|"+type;
    if(cache[key]) return cache[key];
    var g="https://dns.google/resolve?name="+encodeURIComponent(name)+"&type="+type;
    var c="https://cloudflare-dns.com/dns-query?name="+encodeURIComponent(name)+"&type="+type;
    var parse=function(r){if(!r.ok) throw new Error("http "+r.status);return r.json();};
    cache[key]=withTimeout(fetch(g).then(parse),6000).catch(function(){
      return withTimeout(fetch(c,{headers:{accept:"application/dns-json"}}).then(parse),6000);
    }).then(function(j){
      var t={TXT:16,MX:15,CNAME:5,A:1,NS:2}[type];
      var ans=(j.Answer||[]).filter(function(a){return a.type===t;}).map(function(a){return a.data;});
      return {status:j.Status,answers:ans,any:(j.Answer||[]).length>0};
    });
    return cache[key];
  }

  async function spfLookups(record,depth,seen){
    // count DNS-querying terms per RFC 7208 (include, a, mx, ptr, exists, redirect), following includes
    var n=0, terms=record.split(/\s+/);
    for(var i=0;i<terms.length;i++){
      var t=terms[i].replace(/^[+\-~?]/,"").toLowerCase();
      if(/^(a|mx|ptr)(:|\/|$)/.test(t)||/^exists:/.test(t)) n++;
      var inc=t.match(/^include:(.+)$/)||t.match(/^redirect=(.+)$/);
      if(inc){
        n++;
        if(depth<6 && !seen[inc[1]] && n<=12){
          seen[inc[1]]=1;
          try{
            var r=await q(inc[1],"TXT");
            var s=r.answers.map(txtJoin).filter(function(x){return /^v=spf1(\s|$)/i.test(x);})[0];
            if(s) n+=await spfLookups(s,depth+1,seen);
          }catch(e){}
        }
      }
    }
    return n;
  }

  async function check(domain){
    var res={domain:domain,items:{},score:0,provider:null,gateway:null};
    // existence
    var ns=await q(domain,"NS");
    if(ns.status===3){ throw new Error("nxdomain"); }

    // MX
    var mx=await q(domain,"MX");
    var hosts=mx.answers.map(function(d){var p=String(d).split(/\s+/);return {pri:+p[0],host:(p[1]||"").replace(/\.$/,"")};}).filter(function(h){return h.host;}).sort(function(a,b){return a.pri-b.pri;});
    var prov=null;
    hosts.forEach(function(h){ if(!prov) PROVIDERS.forEach(function(p){ if(!prov && p.mx.test(h.host)) prov=p; }); });
    var gw=null; hosts.forEach(function(h){GATEWAYS.forEach(function(g){if(!gw&&g.re.test(h.host)) gw=g.name;});});
    res.provider=prov; res.gateway=gw; res.mx=hosts;
    var nullMx=hosts.length===1&&hosts[0].host==="";
    res.items.mx = hosts.length ? {state:"good",pts:15} : {state:"bad",pts:0};

    // SPF
    var root=await q(domain,"TXT");
    var txts=root.answers.map(txtJoin);
    var spfs=txts.filter(function(x){return /^v=spf1(\s|$)/i.test(x);});
    var spf={records:spfs,issues:[],state:"good",pts:30,lookups:0,senders:[]};
    if(!spfs.length){ spf.state="bad"; spf.pts=0; spf.issues.push("No SPF record. Receivers can't tell which servers may send for you."); }
    else if(spfs.length>1){ spf.state="bad"; spf.pts=5; spf.issues.push("You have "+spfs.length+" SPF records. Only one is allowed, so receivers treat all of them as broken. Merge them into one."); }
    else{
      var s=spfs[0], low=s.toLowerCase();
      if(/(^|\s)\+?all(\s|$)/.test(low) && !/[~\-?]all/.test(low)){ spf.state="bad"; spf.pts=5; spf.issues.push("Your SPF ends in +all, which lets anyone on the internet send as you. Change it to ~all."); }
      else if(/\?all/.test(low)){ spf.state="warn"; spf.pts=18; spf.issues.push("Your SPF ends in ?all (neutral), so it protects nothing. Use ~all."); }
      else if(!/[~\-]all/.test(low) && !/redirect=/.test(low)){ spf.state="warn"; spf.pts=18; spf.issues.push("Your SPF has no ending rule. Add ~all at the end."); }
      if(prov && prov.spf && !prov.spfRe.test(low)){ if(spf.state==="good"){spf.state="warn";spf.pts=18;} spf.issues.push("Your mail runs on "+prov.name+" but SPF doesn't include it ("+prov.spf+"). Your own emails may fail SPF."); }
      SENDERS.forEach(function(x){ if(x.re.test(low)) spf.senders.push(x.name); });
      try{ spf.lookups=await spfLookups(s,0,{}); }catch(e){}
      if(spf.lookups>10){ spf.state="bad"; spf.pts=8; spf.issues.push("Your SPF needs "+spf.lookups+" DNS lookups. The limit is 10, so receivers give up and treat it as failed. Remove services you no longer use."); }
      else if(spf.lookups>=9){ if(spf.state==="good"){spf.state="warn";spf.pts=22;} spf.issues.push("SPF uses "+spf.lookups+" of 10 allowed lookups. One more service will break it."); }
    }
    res.items.spf=spf;

    // DMARC
    var dm=await q("_dmarc."+domain,"TXT");
    var dms=dm.answers.map(txtJoin).filter(function(x){return /^v=dmarc1/i.test(x);});
    var dmarc={records:dms,issues:[],state:"good",pts:30,policy:null};
    if(!dms.length){ dmarc.state="bad"; dmarc.pts=0; dmarc.issues.push("No DMARC record. Gmail rejects bulk mail without one, and anyone can fake emails from your domain."); }
    else if(dms.length>1){ dmarc.state="bad"; dmarc.pts=5; dmarc.issues.push("You have "+dms.length+" DMARC records. Receivers ignore all of them. Keep one."); }
    else{
      var tags={}; dms[0].split(";").forEach(function(p){var kv=p.split("=");if(kv.length>1) tags[kv[0].trim().toLowerCase()]=kv.slice(1).join("=").trim();});
      dmarc.policy=(tags.p||"").toLowerCase(); dmarc.tags=tags;
      if(dmarc.policy==="none"){ dmarc.state="warn"; dmarc.pts=18; dmarc.issues.push("DMARC is in watch-only mode (p=none). That meets Gmail's minimum, but fakes still get delivered. Move to p=quarantine once your reports look clean."); }
      else if(dmarc.policy!=="quarantine" && dmarc.policy!=="reject"){ dmarc.state="bad"; dmarc.pts=5; dmarc.issues.push("Your DMARC record has no valid policy (p=). Receivers ignore it."); }
      if(tags.pct && +tags.pct<100){ if(dmarc.state==="good"){dmarc.state="warn";dmarc.pts=24;} dmarc.issues.push("Only "+tags.pct+"% of mail is covered (pct="+tags.pct+")."); }
      if(!tags.rua){ if(dmarc.state==="good"){dmarc.state="warn";dmarc.pts=26;} else dmarc.pts=Math.max(0,dmarc.pts-3); dmarc.issues.push("No report address (rua). You can't see who sends mail as you."); }
    }
    res.items.dmarc=dmarc;

    // DKIM
    var sels=[]; (prov?prov.dkim:[]).concat(COMMON_SELECTORS).forEach(function(s){ if(sels.indexOf(s)<0) sels.push(s); });
    var found=[];
    await Promise.all(sels.map(function(sel){
      return q(sel+"._domainkey."+domain,"TXT").then(function(r){
        var t=r.answers.map(txtJoin).join("");
        if(/(^|;)\s*p=/i.test(t)){ found.push({sel:sel,revoked:/(^|;)\s*p=\s*(;|$)/i.test(t)}); }
      }).catch(function(){});
    }));
    var live=found.filter(function(f){return !f.revoked;});
    var dkim={found:found,state:live.length?"good":"warn",pts:live.length?25:8,issues:[]};
    if(!live.length){
      dkim.issues.push(found.length?"Your DKIM key at "+found[0].sel+" is switched off (empty key).":"We couldn't find DKIM on the usual names"+(prov?" for "+prov.name:"")+". If it's not set up, Gmail and Yahoo trust your mail less.");
    }
    res.items.dkim=dkim;

    // extras (no points)
    var mta=await q("_mta-sts."+domain,"TXT").catch(function(){return {answers:[]};});
    var bimi=await q("default._bimi."+domain,"TXT").catch(function(){return {answers:[]};});
    res.extras={mtasts:mta.answers.some(function(a){return /v=STSv1/i.test(txtJoin(a));}),bimi:bimi.answers.some(function(a){return /v=BIMI1/i.test(txtJoin(a));})};

    res.score=res.items.mx.pts+spf.pts+dkim.pts+dmarc.pts;
    return res;
  }

  function suggestSpf(res,extra){
    var parts=["v=spf1"];
    (res.items.spf.records.length?res.items.spf.records:["v=spf1"]).forEach(function(r){
      r.split(/\s+/).slice(1).forEach(function(t){
        if(!t || /^[+\-~?]?all$/i.test(t)) return;
        if(parts.map(function(x){return x.toLowerCase();}).indexOf(t.toLowerCase())<0) parts.push(t);
      });
    });
    var add=[]; if(res.provider&&res.provider.spf&&!res.provider.spfRe.test(parts.join(" "))) add.push(res.provider.spf);
    (extra||[]).forEach(function(i){add.push(i);});
    add.forEach(function(a){ if(parts.map(function(x){return x.toLowerCase();}).indexOf(a.toLowerCase())<0) parts.push(a); });
    if(parts.length===1) parts.push("mx");
    parts.push("~all");
    return parts.join(" ");
  }
  function suggestDmarc(res,policy,email){
    var t=(res.items.dmarc.tags)||{};
    var rua=email?("mailto:"+email):(t.rua||("mailto:dmarc@"+res.domain));
    return "v=DMARC1; p="+policy+"; rua="+rua+"; adkim=r; aspf=r; pct=100";
  }

  function tag(state){return {good:"Good",warn:"Needs a look",bad:"Fix this"}[state];}
  function copy(text,btn){
    var done=function(){var o=btn.textContent;btn.textContent="Copied";setTimeout(function(){btn.textContent=o;},1400);};
    if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(text).then(done,function(){fallback();});}else fallback();
    function fallback(){var ta=document.createElement("textarea");ta.value=text;document.body.appendChild(ta);ta.select();try{document.execCommand("copy");done();}catch(e){}document.body.removeChild(ta);}
  }
  function recBlock(label,host,value){
    return '<div class="recrow"><span class="small">'+esc(label)+'</span><dl class="kv"><dt>Type</dt><dd>TXT</dd><dt>Name / Host</dt><dd>'+esc(host)+'</dd></dl><div class="rec">'+esc(value)+'</div><div><button class="btn small ghost" type="button" data-copy="'+esc(value)+'">Copy value</button></div></div>';
  }

  function render(res){
    last=res;
    var d=res.domain, it=res.items;
    $("forDomain").textContent="Results for "+d+(res.provider?" · mail by "+res.provider.name:(res.gateway?" · filtered by "+res.gateway:""));
    var s=res.score;
    $("scoreTxt").textContent=s;
    $("arc").setAttribute("stroke-dashoffset",(314.16*(1-s/100)).toFixed(1));
    $("arc").setAttribute("stroke",s>=85?"#5fd38d":s>=55?"#f5a524":"#ff7a6b");
    var bad=Object.keys(it).filter(function(k){return it[k].state==="bad";}).length;
    var warn=Object.keys(it).filter(function(k){return it[k].state==="warn";}).length;
    $("verdict").textContent = s>=85?"Your email setup looks solid": s>=55?"Some of your emails may land in spam":"Gmail and Outlook have reasons to distrust your mail";
    $("verdictText").textContent = (bad?bad+" thing"+(bad>1?"s":"")+" to fix":"Nothing broken")+(warn?", "+warn+" to look at":"")+". Each card below says what it means and gives the exact record to add.";

    var html="";
    // MX
    html+='<article class="card '+it.mx.state+'"><div class="head"><h3>Who receives your mail (MX)</h3><span class="tag '+it.mx.state+'">'+tag(it.mx.state)+'</span></div>';
    if(res.mx.length){
      html+='<p>'+(res.provider?"Your inbox runs on <b>"+esc(res.provider.name)+"</b>.":res.gateway?"Mail passes through <b>"+esc(res.gateway)+"</b> first.":"Your mail goes to "+esc(res.mx[0].host)+".")+'</p><ul class="plain small">'+res.mx.slice(0,5).map(function(h){return '<li class="mono">'+esc(h.host)+' (priority '+h.pri+')</li>';}).join("")+'</ul>';
    } else html+='<p>No MX records. This domain can\'t receive email, and some receivers distrust mail from domains that can\'t take replies.</p><p class="small">Fix: add the MX records your email provider gives you.</p>';
    html+='</article>';

    // SPF
    var spf=it.spf;
    html+='<article class="card '+spf.state+'"><div class="head"><h3>Who may send as you (SPF)</h3><span class="tag '+spf.state+'">'+tag(spf.state)+'</span></div>';
    if(spf.records.length) html+='<div class="rec">'+esc(spf.records.join("\n"))+'</div>'+(spf.records.length===1?'<p class="small">DNS lookups used: '+spf.lookups+' of 10'+(spf.senders.length?" · also allows "+esc(spf.senders.join(", ")):"")+'</p>':'');
    if(spf.issues.length) html+='<ul class="plain">'+spf.issues.map(function(x){return "<li>"+esc(x)+"</li>";}).join("")+'</ul>'; else html+='<p>One clean SPF record with a proper ending. Good.</p>';
    var sugNow=suggestSpf(res,spf.senders.map(function(n){return SENDERS.filter(function(x){return x.name===n;})[0].inc;}));
    if(spf.state!=="good" && spf.records.length===1 && sugNow.replace(/\s+/g," ").toLowerCase()===spf.records[0].replace(/\s+/g," ").replace(/-all$/i,"~all").toLowerCase()){
      html+='<details open><summary>Fix: get under the lookup limit</summary><p>Your record is written correctly. To get below 10 lookups, remove services you no longer send email from (each include counts), or ask your email provider for a flattened SPF.</p></details>';
    } else if(spf.state!=="good"){
      html+='<details open><summary>Fix: your new SPF record</summary><p class="small">Tick any other service that sends email for you, then copy the record. Replace your old SPF record with this one. Never keep two.</p><div class="svc" id="svc">'+SENDERS.map(function(x,i){return '<label><input type="checkbox" data-inc="'+esc(x.inc)+'"'+(spf.senders.indexOf(x.name)>-1?" checked":"")+'> '+esc(x.name)+'</label>';}).join("")+'</div><div id="spfFix">'+recBlock("Replace your SPF with","@ (or "+d+")",suggestSpf(res,spf.senders.map(function(n){return SENDERS.filter(function(x){return x.name===n;})[0].inc;})))+'</div></details>';
    }
    html+='</article>';

    // DKIM
    var dk=it.dkim;
    html+='<article class="card '+dk.state+'"><div class="head"><h3>Email signature (DKIM)</h3><span class="tag '+dk.state+'">'+tag(dk.state)+'</span></div>';
    var liveSel=dk.found.filter(function(f){return !f.revoked;}).map(function(f){return f.sel;});
    if(liveSel.length) html+='<p>Found DKIM keys at: <span class="mono">'+esc(liveSel.join(", "))+'</span>. Receivers can check your signature.</p>';
    else html+='<ul class="plain">'+dk.issues.map(function(x){return "<li>"+esc(x)+"</li>";}).join("")+'</ul><details open><summary>Fix: switch on DKIM</summary><p>'+esc(res.provider?res.provider.dkimHow:"Open your email provider's admin panel and look for DKIM or 'email authentication'. It gives you one or more records to add to your DNS, then a button to switch signing on.")+'</p></details>';
    html+='</article>';

    // DMARC
    var dm=it.dmarc;
    html+='<article class="card '+dm.state+'"><div class="head"><h3>What to do with fakes (DMARC)</h3><span class="tag '+dm.state+'">'+tag(dm.state)+'</span></div>';
    if(dm.records.length) html+='<div class="rec">'+esc(dm.records.join("\n"))+'</div>';
    if(dm.issues.length) html+='<ul class="plain">'+dm.issues.map(function(x){return "<li>"+esc(x)+"</li>";}).join("")+'</ul>'; else html+='<p>DMARC is enforced and reports are on. Fakes get blocked.</p>';
    if(dm.state!=="good"){
      var startPolicy=(!dm.records.length||dm.policy==="none"||!dm.policy)?(dm.policy==="none"?"quarantine":"none"):dm.policy;
      html+='<details open><summary>Fix: your DMARC record</summary><div class="row" style="gap:12px"><label class="f">Policy<select id="dmPol"><option value="none"'+(startPolicy==="none"?" selected":"")+'>none: watch only (start here)</option><option value="quarantine"'+(startPolicy==="quarantine"?" selected":"")+'>quarantine: fakes go to spam</option><option value="reject"'+(startPolicy==="reject"?" selected":"")+'>reject: fakes are blocked</option></select></label><label class="f">Send reports to<input class="t" id="dmMail" placeholder="dmarc@'+esc(d)+'" value=""></label></div><div id="dmFix">'+recBlock("Add or replace","_dmarc (or _dmarc."+d+")",suggestDmarc(res,startPolicy,""))+'</div><p class="small">Start with none for 2-4 weeks, read the reports, then move to quarantine. Jumping straight to reject can block your own newsletters if a tool you use isn\'t in SPF or DKIM yet.</p></details>';
    }
    html+='</article>';

    // extras
    html+='<article class="card"><div class="head"><h3>Extras</h3><span class="tag">Optional</span></div><ul class="plain small"><li>MTA-STS (forces encrypted delivery): '+(res.extras.mtasts?"set up":"not set")+'</li><li>BIMI (your logo next to emails): '+(res.extras.bimi?"set up":"not set")+'</li></ul><p class="small">Nice to have once SPF, DKIM and DMARC are all green. They don\'t change the score.</p></article>';

    $("cards").innerHTML=html;
    wireFixes(res);
    buildMsg(res);
    $("cta").classList.toggle("hidden", s>=95);
    try{document.title="Inbox Check: "+d+" scored "+s+"/100";}catch(e){}
    $("results").classList.remove("hidden");
  }

  function wireFixes(res){
    var svc=$("svc");
    if(svc) svc.addEventListener("change",function(){
      var inc=[].slice.call(svc.querySelectorAll("input:checked")).map(function(i){return i.getAttribute("data-inc");});
      $("spfFix").innerHTML=recBlock("Replace your SPF with","@ (or "+res.domain+")",suggestSpf(res,inc));
    });
    var pol=$("dmPol"), mail=$("dmMail");
    var upd=function(){ var e=(mail.value||"").trim(); if(e && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e)) e=""; $("dmFix").innerHTML=recBlock("Add or replace","_dmarc (or _dmarc."+res.domain+")",suggestDmarc(res,pol.value,e)); };
    if(pol){pol.addEventListener("change",upd);mail.addEventListener("input",upd);}
  }

  function reportText(res){
    var it=res.items, L=[];
    L.push("Email check for "+res.domain+" (score "+res.score+"/100)");
    L.push("Mail provider: "+(res.provider?res.provider.name:(res.mx[0]?res.mx[0].host:"none found")));
    L.push("");
    L.push("SPF: "+tag(it.spf.state)+(it.spf.records[0]?" | "+it.spf.records[0]:""));
    it.spf.issues.forEach(function(x){L.push("  - "+x);});
    L.push("DKIM: "+tag(it.dkim.state)+(it.dkim.found.length?" | selectors: "+it.dkim.found.map(function(f){return f.sel;}).join(", "):""));
    it.dkim.issues.forEach(function(x){L.push("  - "+x);});
    L.push("DMARC: "+tag(it.dmarc.state)+(it.dmarc.records[0]?" | "+it.dmarc.records[0]:""));
    it.dmarc.issues.forEach(function(x){L.push("  - "+x);});
    if(it.spf.state!=="good") L.push("","Suggested SPF (TXT at @): "+suggestSpf(res,it.spf.senders.map(function(n){return SENDERS.filter(function(x){return x.name===n;})[0].inc;})));
    if(it.dmarc.state!=="good") L.push("Suggested DMARC (TXT at _dmarc): "+suggestDmarc(res,it.dmarc.policy==="none"?"quarantine":"none",""));
    L.push("","Checked with Inbox Check: "+shareUrl(res.domain));
    return L.join("\n");
  }
  function shareUrl(d){return location.origin+location.pathname+"?d="+encodeURIComponent(d);}
  function buildMsg(res){
    var problems=[];
    ["spf","dkim","dmarc"].forEach(function(k){ if(res.items[k].state!=="good") problems.push(k.toUpperCase()); });
    var body="Hi,\n\nPlease fix the email setup for "+res.domain+".\n\nInbox Check score: "+res.score+"/100\nNeeds work: "+(problems.join(", ")||"nothing major")+"\nEmail provider: "+(res.provider?res.provider.name:"not sure")+"\nWhere my DNS is managed (GoDaddy, Cloudflare, Hostinger...): \n\nName:\nCountry:\n";
    $("msg").textContent=body;
    $("mail").textContent=CONFIG.email;
    $("mailBtn").href="mailto:"+CONFIG.email+"?subject="+encodeURIComponent("Email setup fix for "+res.domain)+"&body="+encodeURIComponent(body);
  }

  async function run(raw){
    var d=cleanDomain(raw);
    if(!d){ $("status").innerHTML='<span class="err">That doesn\'t look like a domain. Try yourcompany.com</span>'; return; }
    $("domain").value=d;
    $("go").disabled=true; $("status").textContent="Checking "+d+"…";
    try{
      var res=await check(d);
      render(res);
      $("status").textContent="Checked "+d+" just now.";
      try{ history.replaceState(null,"",shareUrl(d)); }catch(e){}
      setTimeout(function(){ $("results").scrollIntoView({behavior:"smooth",block:"start"}); },60);
    }catch(e){
      $("results").classList.add("hidden");
      $("status").innerHTML='<span class="err">'+(e.message==="nxdomain"?"We couldn't find "+esc(d)+". Check the spelling.":"The DNS lookup didn't answer. Check your connection and try again.")+'</span>';
    }finally{ $("go").disabled=false; }
  }

  $("form").addEventListener("submit",function(e){e.preventDefault();run($("domain").value);});
  [].forEach.call(document.querySelectorAll(".chip"),function(b){b.addEventListener("click",function(){run(b.getAttribute("data-d"));});});
  document.addEventListener("click",function(e){
    var b=e.target.closest&&e.target.closest("[data-copy]"); if(b) copy(b.getAttribute("data-copy"),b);
  });
  $("copyReport").addEventListener("click",function(){ if(last) copy(reportText(last),this); });
  $("shareLink").addEventListener("click",function(){ if(last) copy(shareUrl(last.domain),this); });
  $("copyMsg").addEventListener("click",function(){ copy($("msg").textContent,this); });

  var pre=new URLSearchParams(location.search).get("d");
  if(pre) run(pre);
  window.__inboxCheck={cleanDomain:cleanDomain,txtJoin:txtJoin,suggestSpf:suggestSpf,suggestDmarc:suggestDmarc,check:check,render:render,_q:function(f){q=f;cache={};}};
})();
