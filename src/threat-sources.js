// Only explicitly reviewed providers are eligible for the signed data channel.
// A provider's online/active flag is not independent phishing verification.
export const THREAT_SOURCES = Object.freeze([
 {id:'phishing-database',repository:'Phishing-Database/Phishing.Database',url:'https://github.com/Phishing-Database/Phishing.Database',name:'Phishing.Database',license:'MIT',files:[{path:'phishing-domains-ACTIVE.txt',scope:'domain'},{path:'phishing-links-ACTIVE.txt',scope:'url-host'}]},
 {id:'phishdestroy',repository:'phishdestroy/destroylist',url:'https://github.com/phishdestroy/destroylist',name:'PhishDestroy',license:'MIT',files:[{path:'rootlist/formats/primary_active/domains.txt',scope:'domain'}]},
]);
export const threatSource = url => THREAT_SOURCES.find(source=>source.url===url);
