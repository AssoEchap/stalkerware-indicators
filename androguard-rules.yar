import "androguard"

rule mspy {
    condition:
        androguard.package_name("android.sys.process") or androguard.certificate.sha1("7FFE6DA96346FEE822E1F791176CD6970A1DC770") or androguard.package_name(/.mspy./) or androguard.package_name("system.framework") or androguard.certificate.sha1("3930B621F30D13D24692CBBBBC67C59F92F1C9BD") or androguard.url(/www.mspyonline.com/)
}

rule onetopspy {
    condition:
        androguard.package_name("com.topspy.system") or androguard.certificate.sha1("656CD7890ED79CE8570D1B7156C31958D5AC1606") or androguard.permission(/com.topspy.system.permission/) or androguard.url(/1topspy\.com/)
}

rule mobiispy {
    condition:
        androguard.package_name("com.mobiispy.system") or androguard.url(/mobiispy.com/) or androguard.certificate.sha1("3B167CAE3F1EE3C27DA411DF1290C4CDBA41A633") or androguard.url(/www\.MobiiSpy\.com/) or androguard.certificate.sha1("0208CDD00216157F36DCF7FC2567C5263D8AA682")
}

rule hellospy {
    condition:
        androguard.certificate.issuer(/HelloSpy LLC/) or androguard.certificate.subject(/HelloSpy LLC/) or androguard.url(/hellospy\.com/) or androguard.package_name("com.hellospy.system") or androguard.certificate.sha1("1EBFFD9FE9463B2ED24582D2846990A5ABEF79B9") or androguard.certificate.issuer(/OU=NOVABAY/) or androguard.certificate.subject(/OU=NOVABAY/)
}

rule maxxspy {
    condition:
        androguard.package_name("com.maxxspy.system") or androguard.url(/MaxxSpy\.com/) or androguard.url(/maxxspy\.com/) or androguard.certificate.sha1("6B660EAAEBA47793B7A1278D714669A6612BCA5B")
}

rule nguyen_stalkerware {
    condition:
        androguard.certificate.sha1("7F5C0D54A813BA9B87A91420CA2C3DE5E7948F09") or androguard.app_name(/System Service/) or androguard.url(/\:8080\/gcm-demo/) or androguard.certificate.issuer(/John Nguyen/) or androguard.certificate.subject(/John Nguyen/)
}

rule appspy {
    condition:
        androguard.package_name("com.atracker.app") or androguard.certificate.sha1("0AD33649F0D0532B5EB0A36A81712962AA79BF54") or androguard.certificate.issuer(/OU=ATracker/) or androguard.certificate.subject(/OU=ATracker/) or androguard.url(/appspy\.net/) or androguard.certificate.issuer(/CN=Allen Hitman/) or androguard.certificate.subject(/CN=Allen Hitman/)
}

rule catwatchful {
    condition:
        androguard.package_name("wosc.cwf") or androguard.certificate.issuer(/=catwatchful inc/) or androguard.certificate.subject(/=catwatchful inc/) or androguard.certificate.sha1("9fe876af76cdcb685102a38528a3a732b0872dc6") or androguard.certificate.issuer(/CatWatchful/) or androguard.certificate.subject(/CatWatchful/) or androguard.url(/catwatchful.com/)
}

rule cerberus {
    condition:
        androguard.package_name(/com.lsdroid.cerberus/) or androguard.certificate.sha1("BC693B48B7EC988E275CF9E1CDAA1447A31717D9")
}

rule copy9 {
    condition:
        (androguard.package_name("com.android.system") and androguard.app_name("System Service")) or androguard.certificate.sha1("36E6671BC4397F475A350905D9A649A5ADE97BB2") or androguard.certificate.subject(/iSpyoo Teams/) or androguard.certificate.issuer(/iSpyoo Teams/) or androguard.url(/protocol-a621\.copy9\.com/)
}

rule thetruthspy {
    condition:
        androguard.package_name("com.systemservice") or androguard.url(/\.thetruthspy\.com/) or androguard.certificate.sha1("FF8CCD9816B0524A58FBDE1809FB227DBCDFD692")
}

rule ispyoo {
    condition:
        androguard.package_name("com.ispyoo") or androguard.certificate.sha1("CBDA86758FBE8E5A6AB805F493AA151B1F2B95F4") or androguard.certificate.issuer(/iSpy Solution/) or androguard.certificate.subject(/iSpy Solution/) or androguard.url(/\.ispyoo.com/) or androguard.certificate.sha1("31A6ECECD97CF39BC4126B8745CD94A7C30BF81C") or androguard.certificate.sha1("5D7B59F3AFB74D86CCD56440F99CA2FC83A23F22")
}

rule easylogger {
    condition:
        androguard.package_name("app.EasyLogger") or androguard.certificate.sha1("8F23E1457ADC6189F6ED504A60DF8896FEC6D970") or androguard.package_name("app.ELogger") or androguard.certificate.sha1("35D7CF057BFA5023CE739A725ADA0DA1FD34D1FF")
}

rule flexispy {
    condition:
        (androguard.package_name("com.android.systemupdate") and (androguard.app_name("SystemUpdate") or androguard.app_name("com.android.system.service"))) or androguard.certificate.sha1("69B327860EDB531DDFFB1B5DBF0C24245A75F3E4") or androguard.certificate.sha1("93385A087BB5CAB96EAE83A1AF874E0E39B2990F") or androguard.url(/trkps\.com/) or androguard.package_name("com.telephony.android")
}

rule guestspy {
    condition:
        androguard.package_name("com.guest") or androguard.certificate.sha1("917bb5b2d40ec40018541784a06285de0f50f60f") or androguard.certificate.issuer(/GuestSpy Solution/) or androguard.certificate.subject(/GuestSpy Solution/) or androguard.url(/.guestspy\.com/)
}

rule highstermobile {
    condition:
        androguard.package_name("org.secure.smsgps") or androguard.certificate.sha1("683722A1C629AD5734B93E08ADFAA61775AD196F") or androguard.certificate.subject(/Highsterspyapp/) or androguard.certificate.issuer(/Highsterspyapp/) or androguard.url(/evt17\.com/)
}

rule ddiutilities {
    condition:
        androguard.package_name("com.ddiutilities.monitor") or androguard.url(/ddiutilities\.com/)
}

rule hoverwatch {
    condition:
        androguard.package_name("com.android.core.monitor.debug") or androguard.certificate.sha1("CC4A78DBE96AC1FA5977E03C97052A9A334113B4") or androguard.url(/hoverwatch\.com/) or androguard.package_name("com.android.core.monitor") or androguard.url(/account\.refog\.com/)
}

rule imonitorspy {
    condition:
        androguard.package_name("com.imonitor.ainfo") or androguard.certificate.sha1("BFC4C15E35E3506095B42E2B428E4016B1FFA1AB") or androguard.url(/imonitorsoft\.com/) or androguard.url(/imonitorsoft\.cn/)
}

rule letmespy {
    condition:
        androguard.package_name(/pl.lidwin.letmespy/) or androguard.package_name("pl.lidwin.remote") or androguard.certificate.sha1("8F0EAD4F1DA5DAAF8C0F7A51096CECEEF81D0C76") or androguard.certificate.sha1("340E571CB1A64E6EE384D3F8A544681459CF3F5F") or androguard.url(/letmespy\.com/) or androguard.url(/remotecommands\.com/)
}

rule mxspy {
    condition:
        androguard.package_name("com.mxspy") or androguard.certificate.sha1("56EF5244378FB6B4EF82D2B9E99BF41F7B97D93A") or androguard.certificate.issuer(/MxSpy LCC/) or androguard.url(/\.mxspy\.com/)
}

rule phonespying {
    condition:
        androguard.package_name("com.apspy.app") or androguard.certificate.sha1("D667A33203776F2285EBA3E826CD286356EF05D0") or androguard.certificate.issuer(/PhoneSpying Solution/) or androguard.url(/\.phonespying\.com/)
}

rule repticulus {
    condition:
        androguard.package_name("net.vkurhandler") or androguard.package_name("net.system_updater_abs341") or androguard.certificate.sha1("6D0FF787BF4534F1077D1E4BF2E18BA381D97061") or androguard.url(/reptilicus\.net/)
}

rule shadowspy {
    condition:
        androguard.package_name("com.runaki.synclogs") or androguard.package_name("com.client.requestlogs") or androguard.certificate.sha1("FE7626A8D3C38FD78EA2A729B39B943BA814F014") or androguard.certificate.sha1("01E49C220A9776D4978C1D28D6C32F86D145B8AE") or androguard.url(/\.shadow-logs\.com/)
}

rule spyhide {
    condition:
        androguard.package_name("com.wifiset.service") or androguard.url(/\.spyhide\.com/)
}

rule spyphoneapp {
    condition:
        androguard.package_name("com.spappm_mondow.alarm") or androguard.url(/\.spy-phone-app\.com/) or androguard.url(/\.Spy-datacenter\.com/)
}

rule fonetracker {
    condition:
        androguard.package_name("com.fone") or androguard.certificate.sha1("B0F639B67819EDBADC73B9FEFF2582FC58B8F115") or androguard.certificate.issuer(/FoneTracker Solution/) or androguard.url(/fonetracker\.com/)
}

rule netspy {
    condition:
        androguard.package_name("com.googleplay.settings") or androguard.certificate.sha1("A4E169AAF0068A1FC5F7900B7F59A438B833364C") or androguard.certificate.issuer(/NetSpy LLC/) or androguard.url(/www\.netspy\.net/)
}

rule spyzie {
    condition:
        androguard.package_name("com.spyzee") or androguard.package_name("com.ws.scli") or androguard.package_name("com.ws.sc") or androguard.certificate.sha1("F25D72FCCB84BAF7F73467FC9571024B7E274CA3") or androguard.url(/\.spyzie\.com/) or androguard.url(/\.spyzie\.wondershare\.cn/)
}

rule spymie {
    condition:
        androguard.package_name("com.ant.spymie.keylogger") or androguard.certificate.sha1("05B23C7E9156A4C55768DA27936FF2D7AF09BB8F")
}

rule neospy {
    condition:
        androguard.package_name("ns.antapp.module") or androguard.certificate.sha1("9ED8DD944D3EB545E1EEEEEC1D8174772CF37C07") or androguard.url(/neospy\.pro/) or androguard.url(/neospy\.net/) or androguard.url(/neospy\.tech/)
}

rule androidmonitor {
    condition:
        androguard.package_name("com.ibm.fb") or androguard.certificate.sha1("92EBDB7D7C18A34705A6918B5F327DDB0E8C8452") or androguard.certificate.sha1("558765849658a3821fe4054ed2c1ff6e28b4b8a0") or androguard.url(/\.androidmonitor\.com/)
}

rule alltracker {
    condition:
        androguard.package_name("city.russ.alltrackercorp") or androguard.package_name("city.russ.alltrackerfamily") or androguard.certificate.sha1("43D45CE7BEE36E449434C14973B7D285209414C7") or androguard.url(/alltracker\.org/) or androguard.url(/-dot-all-tracker\.appspot\.com/)
}

rule mobistealth {
    condition:
        androguard.package_name("lookOut.Secure") or androguard.certificate.sha1("FED69D6F09AE8C98DD4053C1934CCAF57D31824D") or androguard.url(/www\.mobistealth\.com/)
}

rule pcTattletale {
    condition:
        androguard.package_name("com.avi.scbase") or androguard.certificate.sha1("20F092BEC76C406223A7943371A1DBBB5BF66C13") or androguard.url(/pctattletale\.com/) or androguard.url(/v4vw4ytvo4\.execute-api\.us-east-2\.amazonaws\.com/)
}
