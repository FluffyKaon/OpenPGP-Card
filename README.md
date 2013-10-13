OpenPGP-Card
============

Open source implementation of the OpenPGP smart card version 2.0 on a java card.

Card Requirements
-----------------
* Java card version 2.2.2 (2.2.1 might work but it is untested)
* 2048 bit RSA key support
* Global platform 2.1.1 or above to use the loading scripts.

The applet was developed and tested on a JCOP 2.4.1 card (NXP J2A080).

Brief instructions
------------------
* Make sure that the card reader is working.
* Install GPShell from http://sourceforge.net/p/globalplatform/wiki/GPShell/
* Loading the applet on the card depend on the card version, the manufacturer and the way it was initialized (pre-personalization).
Warning! Too many failed authentications when trying to load the applet can lock the card and make it unusable.

The 'installJCOP41GPG.gpshell' script provided will work with JCOP 2.4.1 cards using test keys.
To install the applet on the card:
    gpshell installJCOP41GPG.gpshell

* Once the applet is initialized gpg / gpg2 can be used to initialize the card
    gpg2 --card-edit
    admin     // The admin PIN is 12345678, the user PIN is 123456
		generate  // Be aware that the option with backup does not work yet (gpg needs a patch).

For more details check this page: http://wiki.fsfe.org/Card_howtos (but note that the 'with backup' methods will need to patch gpg).