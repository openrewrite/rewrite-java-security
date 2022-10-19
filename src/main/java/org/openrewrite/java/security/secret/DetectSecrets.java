package org.openrewrite.java.security.secret;

import org.openrewrite.ExecutionContext;
import org.openrewrite.Recipe;
import org.openrewrite.SourceFile;
import org.openrewrite.internal.ListUtils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class DetectSecrets extends Recipe {

    @Override
    public String getDisplayName() {
        return "Find Secrets";
    }

    @Override
    protected List<SourceFile> visit(List<SourceFile> before, ExecutionContext ctx) {
        return ListUtils.map(before, sf -> {
            for (SecretConfiguration secretConfiguration : secretConfigurations) {
                sf = secretConfiguration.findSecrets(sf, ctx);
            }
            return sf;
        });
    }

    // WIP
    final SecretConfiguration[] secretConfigurations = new SecretConfiguration[]{
            new ArtifactorySecretConfiguration(),
            new AzureSecretConfiguration(),
            new AwsSecretConfiguration(),
            new DiscordSecretConfiguration()
    };


    // A combination of org.openrewrite.java.search.FindSecrets
    // and https://github.com/Yelp/detect-secrets/tree/master/detect_secrets/plugins
    // some have been moved to SecretConfigurations
    private Map<String, Pattern> originalPatterns() {
        Map<String, Pattern> secretPatterns = new HashMap<>();
        secretPatterns.put("RSA private key", Pattern.compile("-----BEGIN RSA PRIVATE KEY-----"));
        secretPatterns.put("SSH (DSA) private key", Pattern.compile("-----BEGIN DSA PRIVATE KEY-----"));
        secretPatterns.put("SSH (EC) private key", Pattern.compile("-----BEGIN EC PRIVATE KEY-----"));
        secretPatterns.put("PGP private key block", Pattern.compile("-----BEGIN PGP PRIVATE KEY BLOCK-----"));
        secretPatterns.put("Facebook Access Token", Pattern.compile("EAACEdEose0cBA[0-9A-Za-z]+"));
        secretPatterns.put("Facebook OAuth", Pattern.compile("[fF][aA][cC][eE][bB][oO][oO][kK].*['|\"][0-9a-f]{32}['|\"]"));
        secretPatterns.put("Generic API Key", Pattern.compile("[aA][pP][iI]_?[kK][eE][yY].*['|\"][0-9a-zA-Z]{32,45}['|\"]"));
        secretPatterns.put("Generic Secret", Pattern.compile("[sS][eE][cC][rR][eE][tT].*['|\"][0-9a-zA-Z]{32,45}['|\"]"));
        secretPatterns.put("Google API Key", Pattern.compile("AIza[0-9A-Za-z\\-_]{35}"));
        secretPatterns.put("Google Cloud Platform API Key", Pattern.compile("AIza[0-9A-Za-z\\-_]{35}"));
        secretPatterns.put("Google Cloud Platform OAuth", Pattern.compile("[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"));
        secretPatterns.put("Google Drive API Key", Pattern.compile("AIza[0-9A-Za-z\\-_]{35}"));
        secretPatterns.put("Google Drive OAuth", Pattern.compile("[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"));
        secretPatterns.put("Google (GCP) Service-account", Pattern.compile("\"type\": \"service_account\""));
        secretPatterns.put("Google Gmail API Key", Pattern.compile("AIza[0-9A-Za-z\\-_]{35}"));
        secretPatterns.put("Google Gmail OAuth", Pattern.compile("[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"));
        secretPatterns.put("Google OAuth Access Token", Pattern.compile("ya29\\.[0-9A-Za-z\\-_]+"));
        secretPatterns.put("Google YouTube API Key", Pattern.compile("AIza[0-9A-Za-z\\-_]{35}"));
        secretPatterns.put("Google YouTube OAuth", Pattern.compile("[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"));
        secretPatterns.put("Heroku API Key", Pattern.compile("[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"));
        secretPatterns.put("JWT Token", Pattern.compile("eyJ[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*?"));
        secretPatterns.put("MailChimp Access Key", Pattern.compile("[0-9a-z]{32}-us[0-9]{1,2}"));
        secretPatterns.put("MailChimp API Key", Pattern.compile("[0-9a-f]{32}-us[0-9]{1,2}"));
        secretPatterns.put("Mailgun API Key", Pattern.compile("key-[0-9a-zA-Z]{32}"));
        secretPatterns.put("NPM Token", Pattern.compile("//.+/:_authToken=\\s*((npm_.+)|([A-Fa-f0-9-]{36})).*"));
        secretPatterns.put("Password in URL", Pattern.compile("[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]"));
        secretPatterns.put("PayPal Braintree Access Token", Pattern.compile("access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}"));
        secretPatterns.put("Picatic API Key", Pattern.compile("sk_live_[0-9a-z]{32}"));
        secretPatterns.put("SendGrid API Key", Pattern.compile("SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}"));
        secretPatterns.put("Slack Webhook", Pattern.compile("https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}"));
        secretPatterns.put("Stripe API Key", Pattern.compile("sk_live_[0-9a-zA-Z]{24}"));
        secretPatterns.put("Stripe Restricted API Key", Pattern.compile("rk_live_[0-9a-zA-Z]{24}"));
        secretPatterns.put("Square Access Token", Pattern.compile("sq0atp-[0-9A-Za-z\\-_]{22}"));
        secretPatterns.put("Square OAuth Secret", Pattern.compile("sq0csp-[0-9A-Za-z\\-_]{43}"));
        secretPatterns.put("Telegram Bot API Key", Pattern.compile("[0-9]+:AA[0-9A-Za-z\\-_]{33}"));
        secretPatterns.put("Twilio API Key Auth Token", Pattern.compile("SK[0-9a-fA-F]{32}"));
        secretPatterns.put("Twilio API Key Account SID", Pattern.compile("AC[a-z0-9]{32}"));
        secretPatterns.put("Twitter Access Token", Pattern.compile("[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}"));
        secretPatterns.put("Twitter OAuth", Pattern.compile("[tT][wW][iI][tT][tT][eE][rR].*['|\"][0-9a-zA-Z]{35,44}['|\"]"));
        return secretPatterns;
    }
}
