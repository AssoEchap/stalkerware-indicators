# Stalkerware Indicators of Compromise

Indicators of compromise on Stalkerware applications for Android (61 apps so far)

_Warning: these indicators are not providing a complete detection of stalkerware applications. They are based on research from a few people on their free time and many apps are likely missing. Use it carefully. No detection based on these indicators should not be understood as having no stalkerware installed._

## Files

* `androguard-rules.yar` : Androguard yara rules (to be used in [Koodous](https://koodous.com/))
* `appid.yaml` : package ids
* certificates.yaml : Android certificates
* `indicators-for-tinycheck.json` : indicators in [TinyCheck](https://github.com/KasperskyLab/TinyCheck) compatible format
* `misp_event.json` : indicators in [MISP](https://www.misp-project.org/) compatible format
* `network.csv` : list of domains
* `quad9_blocklist.txt` : blocklist for [Quad9 DNS resolver](https://www.quad9.net/) (include a more limited set of domains for apps clearly for stalking and only C2 domains, not app websites)
* `rules.yar` : Yara rules
* `sha256.csv` : sha256 of samples

Scripts:
* `check_apk.py` : check an APK file or APKs in a folder with the indicators from this repository
* `create-indicators-for-tinycheck.py` : creates `indicators-for-tinycheck.json` (automatically done through github actions)
* `make_misp_event.py` : create `misp_event.json` (automatically done through github actions)

## Stalkerware

This repository includes indicators for the following stalkerware :

* 1TopSpy : `www.1topspy.com`
* AllTracker : `alltracker.org` (also called [Russ City](https://www.zscaler.com/blogs/security-research/new-wave-stalkerware-apps))
* AppSpy : `www.appspy.com`
* Android Monitor : `www.androidmonitor.com`
* Catwatchful : `catwatchful.com`
* Cerberus : `www.cerberusapp.com`
* Cocospy : `www.cocospy.com`
* Copy9 : `copy9.com`
* DDI Utilities : `ddiutilities.com`
* EasyLogger : `logger.mobi`
* Espiao Android: `espiaoandroid.com.br`
* FlexiSpy : `www.flexispy.com`
* Free Android Spy : `www.freeandroidspy.com`
* FoneTracker : `fonetracker.com`
* GuestSpy : `guestspy.com` (now replaced by TheTruthSpy)
* HelloSpy : `hellospy.com`
* Highster Mobile : `highstermobile.com`
* Hoverwatch : `www.hoverwatch.com`
* iKeyMonitor : `ikeymonitor.com`
* iMonitorSpy : `www.imonitorsoft.com`
* iSpyoo : `ispyoo.com`
* LetMeSpy : `www.letmespy.com`
* Maxxspy: `maxxSpy.com`
* Meuspy: `meuspy.com`
* MinSpy : `minspy.com`
* Mobispy : `www.mobispy.net`
* Mobiispy : `mobiispy.com`
* MobileTrackerFree : `mobile-tracker-free.com`
* MobileTool : `mtoolapp.net` and `mobiletool.ru`
* Mobistealth : `www.mobistealth.com`
* mSpy : `www.mspy.com`
* MxSpy : `mxspy.com`
* NeatSpy : `neatspy.com`
* NetSpy : `www.netspy.net`
* NeoSpy : `neospy.net` (an analysis [here](https://www.zscaler.com/blogs/security-research/spyware-presence-enterprise-networks))
* pcTattletale : `www.pctattletale.com`
* PhoneSpying : `www.phonespying.com`
* Repticulus : `reptilicus.net`
* SafeSpy : `safespy.com`
* ShadowSpy : `www.shadow-spy.com`
* Snoopza : `snoopza.com`
* SpyApp247 : `www.spyapp247.com`
* SpyHide : `spyhide.com`
* SpyHuman : `spyhuman.com`
* Spyic : `spyic.com`
* Spyier : `spyier.com`
* Spyine : `spyine.com`
* Spylive360 : `spylive360.com`
* SpyMasterPro : `spymasterpro.com`
* Spymie : `www.spymie.com` (analyzed by [ZScaler here](https://www.zscaler.com/blogs/research/why-you-shouldnt-trust-safe-spying-apps))
* SpyPhoneApp : `spyphoneapp.org`
* spy2mobile : `spytomobile.com`
* Spyzie : `www.spyzie.com` `spyzie.io`
* TalkLog : `talklog.tools`
* The One Spy : `theonespy.com`
* TheTruthSpy : `thetruthspy.com`
* Track My Phones : `trackmyphones.com`
* uMobix : `umobix.com`
* WiseMo : `www.wisemo.com`
* WtSpy : `wt-spy.com`
* Xnore : `xnore.com`
* XNSpy : `xnspy.com`

## Contributions

This repository is maintained by the [Echap](https://echap.eu.org/) non-profit organisation.

Contributors include [Anne Roth](https://twitter.com/annalist), [@nscrutables](https://twitter.com/nscrutables), [Abir Ghattas](https://twitter.com/AbirGhattas), [Jurre van Bergen](https://twitter.com/DrWhax)

These indicators were largely based on research and analysis using [APKlab](https://www.apklab.io/), [Koodous](https://koodous.com/) and [VirusTotal](https://www.virustotal.com/).

## Please Contribute

This repository is not complete, new stalkerware apps appear and disappear all the time. Feel free to contribute to this database by opening an issue or submitting a Pull Request.

If you want to do further research on some apps and need access to the samples, feel free to [send me an email](https://www.randhome.io/contact/).

## Other stalkerware repositories

There are other repositories gathering stalkerware indicators:
* [ch33r10 stalkerware list](https://github.com/ch33r10/Stalkerware/tree/master/IOCs)
* [astryzia](https://github.com/astryzia/stalkerware-urls)
* [diskurse android stalkerware](https://github.com/diskurse/android-stalkerware)
* [TinyCheck IOCs](https://github.com/KasperskyLab/TinyCheck/blob/main/assets/iocs.json)

## References

* [Coalition against stalkerware](https://stopstalkerware.org/)
* [Resources from the Clinic to End Tech Abuse](https://www.ceta.tech.cornell.edu/resources)
* [The Predator in Your Pocket - A Multidisciplinary Assessment of the Stalkerware Application Industry](https://citizenlab.ca/2019/06/the-predator-in-your-pocket-a-multidisciplinary-assessment-of-the-stalkerware-application-industry/) by the Citizen Lab
* [What you need to know about stalkerware](https://www.ted.com/talks/eva_galperin_what_you_need_to_know_about_stalkerware/transcript?language=en) - TED Talk by Eva Galperin


## License

Do whatever you want with this data. There is no guarantee that it is accurate. Please contribute if you can. If it is useful to you, consider giving money to an organisation supporting violence against women in your country.
