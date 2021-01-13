# Indicators on Stalkerware

Indicators of compromise on Stalkerware applications for Android

## Files

* `androguard-rules.yar` : Androguard yara rules (to be used in [Koodous](https://koodous.com/))
* `appid.yaml` : package ids
* certificates.yaml : Android certificates
* `indicators-for-tinycheck.json` : indicators in [TinyCheck](https://github.com/KasperskyLab/TinyCheck) compatible format
* `misp_event.json` : indicators in [MISP](https://www.misp-project.org/) compatible format
* `network.csv` : list of domains
* `rules.yar` : Yara rules
* `sha256.csv` : sha256 of samples

Scripts:
* `check_apk.py` : check an APK file or APKs in a folder with the indicators from this repository
* `create-indicators-for-tinycheck.py` : creates `indicators-for-tinycheck.json` (automatically done through github actions)
* `make_misp_event.py` : create `misp_event.json` (automatically done through github actions)

## Stalkerware

This repository includes indicators for the following stalkerware :

* 1TopSpy : `www.1topspy.com`
* AllTracker : `alltracker.org`
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
* Mobispy : `www.mobispy.net`
* Mobiispy : `mobiispy.com`
* MobileTrackerFree : `mobile-tracker-free.com`
* MobileTool : `mtoolapp.net` and `mobiletool.ru`
* Mobistealth : `www.mobistealth.com`
* mSpy : `www.mspy.com`
* MxSpy : `mxspy.com`
* NetSpy : `www.netspy.net`
* NeoSpy : `neospy.net`
* PhoneSpying : `www.phonespying.com`
* Repticulus : `reptilicus.net`
* ShadowSpy : `www.shadow-spy.com`
* Snoopza : `snoopza.com`
* SpyApp247 : `www.spyapp247.com`
* SpyHide : `spyhide.com`
* SpyHuman : `spyhuman.com`
* Spylive360 : `spylive360.com`
* SpyMasterPro : `spymasterpro.com`
* Spymie : `www.spymie.com` (analyzed by [ZScaler here](https://www.zscaler.com/blogs/research/why-you-shouldnt-trust-safe-spying-apps))
* SpyPhoneApp : `spyphoneapp.org`
* spy2mobile : `spytomobile.com`
* Spyzie : `www.spyzie.com`
* TalkLog : `talklog.tools`
* TheTruthSpy : `thetruthspy.com`
* Track My Phones : `trackmyphones.com`
* WiseMo : `www.wisemo.com`
* WtSpy : `wt-spy.com`
* Xnore : `xnore.com`
* XNSpy : `xnspy.com`

## Contributions

This work is done by the [Echap](https://echap.eu.org/) non-profit organisation.

Contributors include [Anne Roth](https://twitter.com/annalist), [@nscrutables](https://twitter.com/nscrutables), [Abir Ghattas](https://twitter.com/AbirGhattas), [Jurre van Bergen](https://twitter.com/DrWhax)

These indicators were largely based on research and analysis using [APKlab](https://www.apklab.io/), [Koodous](https://koodous.com/) and [VirusTotal](https://www.virustotal.com/).

## Please Contribute

This repository is not complete, new stalkerware apps appear and disappear all the time. Feel free to contribute to this database by opening an issue or submitting a Pull Request.

If you want to pursue some research of this app, and need access to some samples, feel free to [send me an email](https://www.randhome.io/contact/).

## References

* [Coalition against stalkerware](https://stopstalkerware.org/)
* [IPVTechResearch : Computer Security and Privacy for Survivors of Intimate Partner Violence](https://www.ipvtechresearch.org/)
* [The Predator in Your Pocket - A Multidisciplinary Assessment of the Stalkerware Application Industry](https://citizenlab.ca/2019/06/the-predator-in-your-pocket-a-multidisciplinary-assessment-of-the-stalkerware-application-industry/) by the Citizen Lab
* [What you need to know about stalkerware](https://www.ted.com/talks/eva_galperin_what_you_need_to_know_about_stalkerware/transcript?language=en) - TED Talk by Eva Galperin
* [Various analysis of Android Stalkerware](https://github.com/diskurse/android-stalkerware) by nscrutables
* [Stalkerware analysis](https://github.com/ch33r10/Stalkerware) by ch33r10

## License

Do whatever you want with this data. There is no guarantee that it is accurate. Please contribute if you can. If it is useful to you, consider giving money to an organisation supporting violence against women in your country.
