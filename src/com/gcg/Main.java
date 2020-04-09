package com.gcg;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.TimeUnit;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.javatuples.Pair;

public class Main {

    public static void main(String[] args) {

        Calendar today = Calendar.getInstance();
        today.set(Calendar.HOUR_OF_DAY, 0);

        List<Pair<String, Long>> expireAliases = new ArrayList<>();

        CommandLine commandLine;
        Option option_keystore = Option.builder("keystore").argName("KeystoreFile").hasArg().desc("Keystore file path").build();
        Option option_truststore = Option.builder("truststore").argName("TruststoreFile").hasArg().desc("Truststore file path").build();
        Option option_type = Option.builder("type").argName("Type").hasArg().desc("Keystore type JKS or  PCK12").build();
        Option option_pass = Option.builder("pass").argName("Password").hasArg().desc("Keystore or Truststore password").build();
        Option option_help = Option.builder("h").argName("Help").desc("List Commands").build();
        //Option option_test = Option.builder().longOpt("test").desc("The test option").build();

        char[] pwdArray = null;
        String filePath = null;
        String type = null;

        Options options = new Options();
        CommandLineParser parser = new DefaultParser();

        options.addOption(option_keystore);
        options.addOption(option_truststore);
        options.addOption(option_pass);
        options.addOption(option_type);
        options.addOption(option_help);

        String header = "               [<arg1> [<arg2> [<arg3> ...\n       Options, flags and arguments may be in any order";
        String footer = "This is DwB's solution brought to Commons CLI 1.3.1 compliance (deprecated methods replaced)";

        try {
            commandLine = parser.parse(options, args);

            if (commandLine.hasOption("pass")) {
                pwdArray = commandLine.getOptionValue("pass").toCharArray();
            }

            if (commandLine.hasOption("keystore")) {
                filePath = commandLine.getOptionValue("keystore");
            }

            if (commandLine.hasOption("type")) {
                type = commandLine.getOptionValue("type");
            }

            if (commandLine.hasOption("h")){
                HelpFormatter formatter = new HelpFormatter();
                formatter.printHelp("Certificate Analyzer", header, options, footer, true);

                return;
            }


            KeyStore ks = KeyStore.getInstance(type);

            if (null == pwdArray) {
                System.out.print("Password :");
                pwdArray = System.console().readPassword();
            }

            ks.load(new FileInputStream(filePath), pwdArray);

            for (Enumeration<String> aliases = ks.aliases();
                 aliases.hasMoreElements(); ) {

                String alias = aliases.nextElement();

                Certificate cert = ks.getCertificate(alias);

                if (null != cert){
                    X509Certificate xcert = (X509Certificate)cert;

                    if (xcert.getNotAfter().compareTo(today.getTime()) > 0)
                    {
                        long diff = xcert.getNotAfter().getTime() - today.getTime().getTime();
                        long day = TimeUnit.DAYS.convert(diff, TimeUnit.MILLISECONDS);
                        if (60L > day)
                            expireAliases.add(new Pair(alias, day));

                    }
                    else
                        expireAliases.add(new Pair(alias, 0));

                }
            }

            for (Pair<String, Long> expireAlias : expireAliases){
                System.out.println("Alias : " + expireAlias.getValue0() + " -- Expire Time : " + expireAlias.getValue1());
            }


        } catch (ParseException exception) {
            System.out.print("Parse error: ");
            System.out.println(exception.getMessage());

            System.out.println("with -h Show all command");
        }
        catch (KeyStoreException ex){
            System.out.println(ex.getMessage());
        }
        catch (CertificateException ex){
            System.out.println(ex.getMessage());
        }
        catch (NoSuchAlgorithmException ex){
            System.out.println(ex.getMessage());
        }
        catch (IOException ex){
            System.out.println(ex.getMessage());
        }
    }
}
