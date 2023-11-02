# Stalkerware Indicators of Compromise

Indicators of compromise (IOC) for Stalkerware and Watchware applications for Android and iOS

_Warning: these indicators are not providing a complete detection of
stalkerware applications. They are based on research from a few people on their
free time and many apps are likely missing. Use it carefully. No detection
based on these indicators should not be understood as having no stalkerware
installed._

**If you think you may be victim of a stalkerware application, check [this page](https://stopstalkerware.org/information-for-survivors/)**

This repository is maintained by [Julien Voisin](https://dustri.org/), and [Tek](https://github.com/Te-k) for the [Echap](https://echap.eu.org/) non-profit organisation.

## What's a stalkerware?

We're using the definition of the [Coalition Against Stalkerware](https://stopstalkerware.org/):

> Stalkerware refers to tools – software programs, apps and devices – that
enable someone to secretly spy on another person’s private life via their
mobile device. The abuser can remotely monitor the whole device including web
searches, geolocation, text messages, photos, voice calls and much more. Such
programs are easy to buy and install. They run hidden in the background,
without the affected person knowing or giving their consent. Regardless of
stalkerware’s availability, the abuser is accountable for using it as a tool
and hence for committing this crime.

We are classifying as watchware any application that is developed for surveillance and is not trying to hide its activity (like a child monitoring application).

## IOC

Main files:

* `ioc.yaml` : Indicators of compromise of many Stalkerware apps. Includes
    * [Applications Package names](https://support.google.com/admob/answer/9972781)
    * [Android Application Certificates](https://support.google.com/googleplay/android-developer/answer/9842756?hl=en)
    * List of websites
    * List of domains and IPs of [C2](https://en.wikipedia.org/wiki/Botnet#Command_and_control)
* `watchware.yaml` : Indicators of compromise of watchware apps
* `samples.csv`: List of samples with hashes, package name, certificate and version.

Files generated automatically from previous Stalkerware IOC files:

* `generated/hosts`: network indicators (C2 stalkerware domains only) in hosts format
* `generated/hosts_full`: network indicators (C2 domains only for both stalkerware and watchware) in hosts format
* `generated/indicators-for-tinycheck.json`: indicators in [TinyCheck](https://github.com/KasperskyLab/TinyCheck) compatible format (Stalkerware only)
* `generated/misp_event.json`: indicators in [MISP](https://www.misp-project.org/) compatible format (Stalkerware only)
* `generated/network.csv`: network indicators in a more grepable CSV format (Stalkerware only)
* `generated/quad9_blocklist.txt`: blocklist for [Quad9 DNS resolver](https://www.quad9.net/)
* `generated/stalkerware.stix2`: indicators in [STIX2](https://oasis-open.github.io/cti-documentation/stix/intro) format (stalkerware and watchware)
* `generated/suricata.rules`: [Suricata](https://suricata.io/) rules for network indicators (Stalkerware C2 only)

## Stalkerware

This repository includes indicators for 164 applications (139 stalkerware and 25 watchware) and 2940 samples

List of stalkerware apps:

* AbsoluTrack (`absolutesoftsystem.in` `absolutestoreindia.com` `ass.absolutesoftsystem.in` `geniesoftsystem.com` `onetouchsecurities.com` `smartguardapp.com` `thiefguardbd.com` `www.smartguardapp.com`)
* Ahmyth
* AiSpyer (`aivideoedit.com` `aispyer.com` `www.aispyer.com`)
* AllTracker (`alltracker.org`)
* Android007 (`android007.com` `www.android007.com` `portal.android007.com` `spybunker.com` `www.spybunker.com`)
* AndroidLost (`androidlost.com` `www.androidlost.com`)
* AndroidMonitor (`androidmonitor.com` `demo.ultimatephonespy.com` `ultimatephonespy.com` `www.androidmonitor.com` `my.androidmonitor.com`)
* AndroidPolice (`amon.android-monitor.ru` `amon1.android-monitor.ru` `andmon.name` `android-apk.android-monitor.ru` `android-monitor.ru` `android-monitor1.android-monitor.ru` `android-police.android-monitor.ru` `android-police.ru` `anmon.android-monitor.ru` `anmon.name` `anmon.ru` `anmon.su` `anmon1.android-monitor.ru` `droimon20.ru` `monitor-android.android-monitor.ru` `prog-money.android-monitor.ru` `prog-money.com` `www.android-monitor.ru`)
* AndroidSpy (`a-spy.com` `www.a-spy.com`)
* AndroidSpyApp
* AntiFurtoDroid (`antifurtodroid.com`)
* AppMia (`appmia.com` `appmia.com.es` `appmia.it` `appmia.fr` `cp.appmia.com`)
* AppSpy (`app.appspy.net` `app.appspyfree.com` `app.freephonespy.net` `app.mobilespyfree.net` `appspy.com` `appspy.net` `appspyfree.com` `apptracker.net` `cellphonespyappon.com` `free-spy.com` `free.apptracker.net` `freemobilespy.net` `freephonespy.net` `justseries.net` `mobilespyfree.net` `spyren.com` `trackerfree.net` `www.appspy.com` `www.appspy.net` `www.apptracker.net` `www.cellphonespyappon.com` `www.freemobilespy.net` `www.freephonespy.net` `www.mobilespyfree.net` `www.spyren.com` `www.trackerfree.net` `www.xvids.us` `xvids.us`)
* BlurSpy (`www.blurspy.com` `blurspy.com` `xoxospy.com`)
* BosSpy (`bosspy.com`)
* Bulgok (`c-phone.ru`)
* CallSMSTracker (`callsmstracker.com` `hiddensmstracker.com` `hiddensystemhealth.com` `registrations.smstracker.com` `smstracker.com` `smstrackerweb.com` `www.hiddensmstracker.com` `www.hiddensystemhealth.com` `www.smstrackerweb.com`)
* CatWatchful (`catwatchful.com` `catwatchful.online`)
* Cerberus (`cellphonetrackers.org` `cerberusapp.com` `cerberusbrasil.com` `enterprise.cerberusapp.com` `www.cerberusapp.com` `www.cerberusbrasil.com`)
* ClevGuard (`clevguard.net` `www.clevguard.com` `clevguard.com` `panel.clevguard.com`)
* Cocospy (`best-mobile-spy.com` `cocospy.com` `cocospy.net` `fonemonitor.co` `minspy.com` `neatspy.com` `safespy.com` `spyic.biz` `spyic.com` `spyier.biz` `spyine.biz` `spyine.com` `spyzie.com` `spyzie.io` `spyzie.online` `teensafe.net` `teensoftware.com` `www.fonemonitor.co` `www.minspy.com` `www.spyic.com` `www.spyzie.com` `www.teensafe.net` `www.teensoftware.com`)
* CouplerTracker (`coupletracker.com`)
* Curiosus
* Dash
* DroidWatcher
* EasyLogger (`logger.mobi` `childsafetytrackerapp.com` `seniorsafetyapp.com` `www.childsafetytrackerapp.com` `www.seniorsafetyapp.com`)
* EasyPhoneTrack (`spappmonitoring.com` `www.spappmonitoring.com` `mobil-kem.com` `easyphonetrack.com`)
* EspiaoAndroid (`foxspy.com.br`)
* EvaSpy (`evaspy.com` `login.evaspy.com` `spyrix.com` `www.spyrix.com`)
* Fenced (`mobilespy.io` `fenced.ai` `web.mobilespy.io` `demo.fenced.ai` `web.fenced.ai` `admin.fenced.ai`)
* FindMyKids (`findmykids.org`)
* FindMyPhone (`find-myphone.com`)
* FlashKeylogger (`flashkeylogger.com`)
* FlexiSpy (`flexispy.com` `community.flexispy.com` `blog.flexispy.com` `www.flexispy.com` `mobilefonex.com` `mobileapps.com.my` `flexispy.mobileapps.com.my` `svlogin.asia`)
* FreeAndroidSpy (`freeandroidspy.com`)
* GPSTrackerLoki (`asgardtech.ru`)
* HelloSpy (`1topspy.com` `account.mobile-remote-tracker.com` `alospy.com` `getspyapps.com` `hellospy.com` `innovaspy.com` `ispytic.com` `maxxspy.com` `mobeespy.com` `mobellspy.com` `mobiispy.com` `mobile-remote-tracker.com` `mobilespyblog.com` `mspymax.com` `opispy.net` `spyacellphone.com` `spyhide.com` `spyhide.ir` `spyios8x.com` `www.spyhide.com` `www.spyhide.ir`)
* HighsterMobile (`auto-forward.com` `autoforward.app` `autoforward.co` `bestcellphonespyapps.com` `buyeasyspy.com` `cellphoneservices.info` `ddiutilities.com` `dev.safeguarde.com` `digitalsecurityworld.com` `evt17.com` `highstermobile.co` `highstermobile.com` `ilfmobileapps.com` `m.surepointspy.com` `phonespector.com` `safeguarde.com` `surepointspy.com` `thepowerlinegroup.com` `turbophonepsy.com` `www.surepointspy.com`)
* Hoverwatch (`br.refog.com` `de.refog.com` `es.refog.com` `fr.refog.com` `hover.watch` `hoverwatch.com` `hu.refog.com` `hws.icu` `it.refog.com` `my.hws.icu` `nl.refog.com` `prospybubble.com` `refog.com` `refog.de` `refog.net` `refog.org` `ro.refog.com` `www.hoverwatch.com` `www.refog.com`)
* ISpy
* Intertel (`mobile-spy.co.za`)
* KidSecured (`kidsecured.com`)
* KidsShield (`backupsoft.eu` `freespyapp.com` `kidlogger.net` `kidsshield.net` `monitorminor.com.tr` `pc.freespyapp.com` `pc.selfspy.com` `selfspy.com` `spytrac.com` `techinnovative.net` `tifamily.net` `tispy.net` `tracerspy.net` `ua.tispy.net` `viptelefonprogrami.com` `www.kidlogger.net` `www.selfspy.com`)
* LetMeSpy (`letmespy.com` `remotecommands.com` `www.letmespy.com` `www.teleszpieg.pl` `teleszpieg.pl` `bbiindia.com` `www.bbiindia.com`)
* LoveSpy
* Metasploit (`foreverspy.com`)
* MeuSpy (`meuspy.com` `monitorecell.com.br` `espiao.meuspy.com` `www.espiaodecelulargratis.com.br` `espiaodecelulargratis.com.br`)
* MobiSpy (`mobispy.net`)
* MobiStealth (`mobistealth.com` `www.mobistealth.com` `www.mobilestealthreview.com`)
* MobileSpy (`de.mobilespy.at` `es.mobilespy.at` `fr.mobilespy.at` `it.mobilespy.at` `mobilespy.at` `pt.mobilespy.at` `ro.mobilespy.at` `www.mobilespy.at`)
* MobileTool (`mobiletool.ru` `www.mobiletool.ru` `mtoolapp.net` `www.mtoolapp.net` `mtoolapp.biz`)
* MobileTrackerFree (`br.mobile-tracker-free.com` `br.loverman.net` `celltracker.io` `loverman.net` `mobile-tracker-family.com` `mobile-tracker-free.be` `mobile-tracker-free.biz` `mobile-tracker-free.co` `mobile-tracker-free.com` `mobile-tracker-free.de` `mobile-tracker-free.es` `mobile-tracker-free.eu` `mobile-tracker-free.fr` `mobile-tracker-free.info` `mobile-tracker-free.ir` `mobile-tracker-free.it` `mobile-tracker-free.me` `mobile-tracker-free.mobi` `mobile-tracker-free.name` `mobile-tracker-free.net` `mobile-tracker-free.org` `support.mobile-tracker-free.com` `support.loverman.net` `mobile-tracker.mobi` `mobitrackapps.com`)
* MocoSpy (`mocospy.com`)
* MonitorUltra (`www.spyequipmentuk.co.uk`)
* Mrecorder (`mobilerecorder24.com` `mrecorder.com`)
* MyCellSpy (`mycellspy.com` `cezz.me` `user.mycellspy.com`)
* MySpyApps (`myspyapps.com`)
* MzanziSpy (`mzanzispy.co.za`)
* NemoSpy (`nemospy.com` `admin.nemospy.com`)
* NeoSpy (`neospy.pro` `neospy.net` `neospy.tech` `ru.neospy.net`)
* NetSpy (`www.netspy.net` `netspy.net`)
* NexSpy (`nexspy.com` `oxy.nexspy.com` `mobilebackup.biz` `portal.mobilebackup.biz` `portal.topzaloha.cz`)
* Observer (`www.observer.pw`)
* OneLocator (`locatorprivacy.com` `onelocator.com`)
* OneSpy (`onemonitar.com` `onespy.com` `cloud.onemonitar.com` `send.onemonitar.com` `test.send.onemonitar.com` `superuser.onemonitar.com` `su.onemonitar.com` `cp.onemonitar.com` `app.onemonitar.com` `send.onespy.com`)
* OwnSpy (`mobileinnova.net` `ownspy.com` `en.ownspy.com` `webdetetive.com.br` `ownspy.es` `saferspy.com` `panel.webdetetive.com.br` `era3000.com`)
* PanSpy (`panspy.com` `surveilstar.com`)
* PatanSpyApp
* PhoneMonitor
* PhoneSheriff (`www.mobile-spy.com` `www.emobilespy.com` `phonesheriff.com` `www.phonesheriff.com` `www.retinax.com` `retinax.com`)
* PhoneSpy (`www.phone-spy.com` `phone-spy.com` `aksoft.gq`)
* RastreadorDeNamorado (`rastreadordenamorado.com.br`)
* RealtimeSpy (`www.spytech-web.com` `spytech-web.com` `realtime-spy-mobile.com` `www.realtime-spy-mobile.com`)
* RecomSpy (`recomspy.com`)
* Reptilicus (`reptilicus.net` `thecybernanny.com` `apollospy.com`)
* RioSPY (`www.riospy.net` `riospy.net`)
* SMSForward
* SecretCamRecorder
* SentryPC (`www.sentrypc.com` `sentrypc.com`)
* ShadowSpy (`shadow-logs.com` `shadow-spy.com` `www.shadow-logs.com` `www.shadow-spy.com`)
* ShadySpy (`shadyspy.com` `www.shadyspy.com`)
* SmartKeylogger (`awamisolution.com`)
* Snoopza (`snoopza.com` `get.snoopza.com` `snoopza.zendesk.com` `demo.snoopza.com` `newdemo.snoopza.com`)
* Spy24 (`spy24.net` `spy24.app`)
* SpyAdvice (`spyadvice.com` `freespyphone.net`)
* SpyApp (`accounts.spyapp.ro` `accounts.pgv4.com` `applispy.com` `area.spyapp.ch` `beta.spyapp.ro` `br.pgv4.com` `clienti.securspy.com` `compte.applispy.com` `controllo.spystoreitalia.com` `tel.forensis-lab.com` `mespiao.com.br` `partner.securspy.com` `pgv4.com` `pin.pgv4.com` `pin.spyapp.ro` `ro.pgv4.com` `roaccount.pgv4.com` `securspy.com` `server.pgv4.com` `spyapp.at` `spyapp.ch` `spyapp.es` `spyapp.fr` `spyapp.uk` `spyapp.ro` `spybrother.com` `sys.spyapp.ch` `www.spyapp.ch` `www.spyapp.ro` `x.securspy.com` `x.spyapp.ro`)
* SpyApp247
* SpyAppGhazi
* SpyDroid
* SpyEra (`spyera.com` `login.spylogs.com` `support.spyera.com` `affiliate.spyera.com`)
* SpyFly (`spyfly.co.za`)
* SpyHuman (`spyhuman.com` `services.spyhuman.com`)
* SpyKontrol (`www.spykontrol.com` `spykontrol.com` `androidapk.biz`)
* SpyLive360 (`spylive360.com` `www.spylive360.com`)
* SpyMasterPro (`spymasterpro.com` `www.spymasterpro.com`)
* SpyMug
* SpyNote (`www.spynote.us` `spynote.us`)
* SpyPhoneApp
* SpySMS
* SpyTec (`spytecgps.io` `spytecgl300.com` `www.spytec.com` `spytec.com` `activation.spytec.com`)
* SpyTek (`spytekonline.co.za` `spytek.co.za` `portal.spytek.co.za`)
* SpyToApp (`spytoapp.com`)
* Spyier (`spyier.com`)
* Spylix (`spylix.com` `www.spylix.com`)
* Spymie
* SpyphoneMobileTracker (`phonetracker.com` `www.phonetracker.com` `spyfone.com` `spyphone.com` `www.spyphone.com` `spy-phone-app.com`)
* Spyzier
* SwiftMobileSpy (`pc.myswiftmobilespy.co.za` `swiftmobilespy.co.za`)
* TalkLog (`talklog.tools`)
* TheOneSpy (`theonespy.com` `ogymogy.com` `www.theonespy.com`)
* TheTruthSpy (`app.phonespying.com` `copy9.com` `exactspy.com` `fonetracker.com` `free.spycell.net` `guestspy.com` `hespyapp.com` `innoaspy.com` `ispyoo.com` `mobidad.app` `mobilespyonline.com` `mxspy.com` `phonespying.com` `phonetracking.net` `secondclone.com` `spyapps.net` `spycell.net` `thespyapp.com` `thetruthspy.com` `weysys.com` `www.mxspy.com` `www.phonespying.com` `xpspy.com`)
* TheWiSpy (`www.thewispy.com` `childmonitoringsystem.com`)
* Traccar (`www.traccar.org` `demo.traccar.org` `traccar.org`)
* TrackMyPhones (`trackmyphones.com` `www.trackmyphones.com`)
* TrackView (`chome.zstone.co` `lifecircle.app` `trackview.net` `trackview.recurly.com`)
* TrackingSmartphone (`trackingsmartphone.com` `www.trackingsmartphone.com` `onlinefundb.com`)
* Trackji (`trackji.com`)
* Trackplus (`account.spytomobile.com` `forum.spytomobile.com` `spy2mobile.com` `spytomobile.com` `trackerplus.ru` `www.spy2mobile.com` `www.spytomobile.com`)
* Tracku (`2mata.net` `clues4.com` `cluestr.com` `e-spy.org` `hike.in` `izkid.com` `www.e-spy.org` `www.izkid.com`)
* Unisafe (`usafe.ru` `unisafe.su` `unisafe.techmas.ru`)
* VIPTrack (`viptrack.ro`)
* WebWatcher (`awarenesstechnologies.com` `interguardsoftware.com` `screentimelabs.com` `webwatcher.com` `www.webwatcher.com`)
* WheresMyDroid (`wheresmydroid.com` `www.wheresmydroid.com` `wmdcommander.appspot.com`)
* WiseMo (`www.wisemo.com` `wisemo.com`)
* WtSpy (`wt-spy.com`)
* XDSpy (`xdspy.app` `androidspy.info`)
* XNSpy (`xnspy.com` `cp.xnspy.com`)
* Xnore (`xnore.com`)
* XploitSPY (`xploitwizer.com`)
* bark (`bark.us` `www.bark.us`)
* iKeyMonitor (`easemon.com`)
* iMonitorSpy (`www.imonitorsoft.cn` `www.imonitorsoft.com` `imonitorsoft.cn`)
* jjspy (`www.jjspy.com` `www.ttspy.com`)
* juju (`www.juju.co.ke` `juju.co.ke`)
* mSpy (`cart.mspy.com` `mliteapp.com` `mspy.co.il` `mspy.co.uk` `mspy.com` `mspy.com.ar` `mspy.com.br` `mspy.com.cn` `mspy.fr` `mspy.in` `mspy.it` `mspy.jp` `mspy.net` `mspy.nl` `mspy.support` `mspylite.com` `mspyplus.com` `www.eyezy.com` `mspyonline.com` `myfonemate.com` `theispyoo.com` `www.mspyonline.com` `www.mspy.com` `freefonespy.com`)
* mSpyitaly (`dc-407883c18502.mspyitaly.com` `mspyitaly.com` `www.mspyitaly.com`)
* pcTattletale (`www.pctattletale.com`)
* uMobix (`umobix.com` `n.umobix.com` `spyfer.info` `surveillance-enfants.com`)
* xHunter

## Notable users

- [AdGuard](https://github.com/AdguardTeam/HostlistsRegistry/pull/35)
- [Quad9 DNS resolver](https://www.quad9.net/)
- [oisd blocklist full](https://oisd.nl/downloads)
- [IPV Spyware Discovery](https://github.com/stopipv/isdi)
- [The Mobile Verification Toolkit](https://github.com/mvt-project/mvt)
- [StratosphereIPS](https://github.com/stratosphereips/StratosphereLinuxIPS)
- [the Hypatia malware scanner](https://github.com/Divested-Mobile/Hypatia)

## Contributions

Contributors include:

- [Abir Ghattas](https://twitter.com/AbirGhattas)
- [Anne Roth](https://twitter.com/annalist)
- [Jo Coscia](https://github.com/jcoscia)
- [Jurre van Bergen](https://twitter.com/DrWhax)
- [@nscrutables](https://twitter.com/nscrutables)
- [Joan](https://github.com/j04n)

These indicators are largely based on research and analysis using [APKlab](https://www.apklab.io/), [Koodous](https://koodous.com/) and [VirusTotal](https://www.virustotal.com/).

## Please Contribute

This repository is not complete, new stalkerware apps appear and disappear all the time. Feel free to contribute to this database by opening an issue or submitting a Pull Request.

If you want to contribute, fork this repository, make your changes into the branch `research` and submit a Pull Request. Once merged, a GitHub Action will automatically generate the different files available on the `master` branch.

If you want to do further research on some apps and need access to the samples, feel free to send us an email at contact AT echap.eu.org.

## Other stalkerware repositories

There are other repositories gathering stalkerware indicators:
* [ch33r10 stalkerware list](https://github.com/ch33r10/Stalkerware/tree/master/IOCs)
* [astryzia](https://github.com/astryzia/stalkerware-urls)
* [diskurse android stalkerware](https://github.com/diskurse/android-stalkerware)
* [TinyCheck IOCs](https://github.com/KasperskyLab/TinyCheck/blob/main/assets/iocs.json)

## References

* [Echap - Lutter contre les stalkerware](https://echap.eu.org/lutter-contre-les-stalkerwares/)
* [Coalition against stalkerware](https://stopstalkerware.org/)
* [Resources from the Clinic to End Tech Abuse](https://www.ceta.tech.cornell.edu/resources)
* [The Predator in Your Pocket - A Multidisciplinary Assessment of the Stalkerware Application Industry](https://citizenlab.ca/2019/06/the-predator-in-your-pocket-a-multidisciplinary-assessment-of-the-stalkerware-application-industry/) by the Citizen Lab
* [What you need to know about stalkerware](https://www.ted.com/talks/eva_galperin_what_you_need_to_know_about_stalkerware/transcript?language=en) - TED Talk by Eva Galperin

## License

The content of this repository is licensed under [CC-BY](https://creativecommons.org/licenses/by/4.0/). If this license is a problem for you, please reach out (contact AT echap.eu.org), we are happy to figure something out.

Please note that while we're doing our very best, there is no guarantee that it is accurate.
If it is useful to you, consider giving money to an organisation supporting violence against women in your country.


