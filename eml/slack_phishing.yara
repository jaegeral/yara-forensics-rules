/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html)
    and open to any user or organization, as long as you use it under this license.

*/

rule slack_phishing
{
         meta:
        author = "Alexander Jaeger"
        desc = "suspicious slack links in files / eml"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        version = "v0.1"
        weigth = 80
        reference = "https://twitter.com/PhishingAi/status/1125759292081037312"
    strings:
        $a = "www-slack.com" nocase
        $b = "slack-email.com" nocase
        $c = "slack-mail.com" nocase
        $d = "slack-message.com" nocase
        $e = "slack-notification.com" nocase
        $f = "messageslack.com" nocase
        $g = "online-slack.com" nocase
        $h = "slackmessage.com" nocase
        $i = "slackdevelopment.info" nocase
        $j = "slack-autoresponder.com" nocase
        $k = "slackautoresponder.com" nocase
    condition:
        any of them
}