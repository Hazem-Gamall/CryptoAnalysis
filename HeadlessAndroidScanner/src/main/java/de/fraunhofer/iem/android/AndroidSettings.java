/********************************************************************************
 * Copyright (c) 2017 Fraunhofer IEM, Paderborn, Germany
 * <p>
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 * <p>
 * SPDX-License-Identifier: EPL-2.0
 ********************************************************************************/
package de.fraunhofer.iem.android;

import com.google.common.io.Files;
import crypto.exceptions.CryptoAnalysisParserException;
import crypto.reporting.Reporter;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.*;
import java.util.concurrent.Callable;

import picocli.CommandLine;

@CommandLine.Command(mixinStandardHelpOptions = true)
public class AndroidSettings implements Callable<Integer> {

    @CommandLine.Option(
            names = {"--apkFile"},
            description = {"The absolute path to the .apk file"},
            required = true)
    private String apkFile = null;

    @CommandLine.Option(
            names = {"--platformDirectory"},
            description = "The absolute path to the android SDK platforms",
            required = true)
    private String platformDirectory = null;

    @CommandLine.Option(
            names = {"--rulesDir"},
            description = {
                    "The path to ruleset directory. Can be a simple directory or a ZIP archive"
            },
            required = true)
    private String rulesetDirectory = null;

    @CommandLine.Option(
            names = {"--cg"},
            description = {"The call graph algorithm"})
    private String cgAlgorithm = null;

    @CommandLine.Option(
            names = {"--reportPath"},
            description = "Path to a directory where the reports are stored")
    private String reportPath = null;

    @CommandLine.Option(
            names = {"--reportFormat"},
            split = ",",
            description =
                    "The format of the report. Possible values are CMD, TXT, SARIF, CSV and CSV_SUMMARY (default: CMD)."
                            + " Multiple formats should be split with a comma (e.g. CMD,TXT,CSV)")
    private String[] reportFormat = null;

    @CommandLine.Option(
            names = {"--visualization"},
            description = "Visualize the errors (requires --reportPath to be set)")
    private boolean visualization = false;

    @CommandLine.Option(
            names = {"--ignoreSections"},
            description =
                    "Names of packages, classes and methods to be ignored during the analysis. This "
                            + "input expects path to a file containing one name per line. For example, "
                            + "'de.example.testClass' ignores the class 'testClass', 'de.example.exampleClass.exampleMethod "
                            + "ignores the method 'exampleMethod' in 'exampleClass', and 'de.example.*' ignores all classes "
                            + "and methods in the package 'example'. Using this option may increase the analysis performance. "
                            + "Note that constructors are methods that can be specified with '<init>'.")
    private String ignoreSectionsPath = null;

    @CommandLine.Option(
            names = {"--timeout"},
            description =
                    "Timeout for seeds in milliseconds. If a seed exceeds this value, CryptoAnalysis aborts the "
                            + "typestate and extract parameter analysis and continues with the results computed so far. (default: 10000)")
    private int timeout = 10000;

    public enum CallGraphAlgorithm {
        CHA,
        RTA,
        VTA,
        SPARK
    }

    private CallGraphAlgorithm callGraphAlgorithm;
    private Collection<String> ignoredSections;
    private Collection<Reporter.ReportFormat> reportFormats;

    public AndroidSettings() {
        callGraphAlgorithm = CallGraphAlgorithm.CHA;
        reportFormats = Set.of(Reporter.ReportFormat.CMD);
    }

    public void parseSettingsFromCLI(String[] settings) throws CryptoAnalysisParserException {
        CommandLine parser = new CommandLine(this);
        parser.setOptionsCaseInsensitive(true);
        int exitCode = parser.execute(settings);

        if (cgAlgorithm != null) {
            callGraphAlgorithm = parseCallGraphAlgorithm(cgAlgorithm);
        }

        if (reportFormat != null) {
            reportFormats = parseReportFormatValues(reportFormat);
        }

        if (ignoreSectionsPath != null) {
            ignoredSections = parseIgnoredSectionOption(ignoreSectionsPath);
        }

        if (visualization && reportPath == null) {
            throw new CryptoAnalysisParserException(
                    "If visualization is enabled, the reportPath has to be set");
        }
        if (timeout < 0) {
            throw new CryptoAnalysisParserException("Timeout should not be less than 0");
        }

        if (exitCode != CommandLine.ExitCode.OK) {
            throw new CryptoAnalysisParserException("Error while parsing the CLI arguments");
        }
    }

    private CallGraphAlgorithm parseCallGraphAlgorithm(String algorithm) {
        return switch (algorithm.toLowerCase()) {
            case "cha" -> CallGraphAlgorithm.CHA;
            case "rta" -> CallGraphAlgorithm.RTA;
            case "vta" -> CallGraphAlgorithm.VTA;
            case "spark" -> CallGraphAlgorithm.SPARK;
            default -> throw new CryptoAnalysisParserException(
                    "Invalid call graph algorithm. Possible values are {CHA, RTA, VTA, SPARK");
        };
    }

    private Collection<Reporter.ReportFormat> parseReportFormatValues(String[] settings) {
        Collection<Reporter.ReportFormat> formats = new HashSet<>();

        for (String format : settings) {
            String reportFormatValue = format.toLowerCase();

            switch (reportFormatValue) {
                case "cmd":
                    formats.add(Reporter.ReportFormat.CMD);
                    break;
                case "txt":
                    formats.add(Reporter.ReportFormat.TXT);
                    break;
                case "sarif":
                    formats.add(Reporter.ReportFormat.SARIF);
                    break;
                case "csv":
                    formats.add(Reporter.ReportFormat.CSV);
                    break;
                case "csv_summary":
                    formats.add(Reporter.ReportFormat.CSV_SUMMARY);
                    break;
                case "github_annotation":
                    formats.add(Reporter.ReportFormat.GITHUB_ANNOTATION);
                    break;
                default:
                    throw new CryptoAnalysisParserException(
                            "Incorrect value "
                                    + reportFormatValue
                                    + " for --reportFormat option. "
                                    + "Available options are: CMD, TXT, SARIF, CSV and CSV_SUMMARY.\n");
            }
        }

        return formats;
    }

    private Collection<String> parseIgnoredSectionOption(String path)
            throws CryptoAnalysisParserException {
        Collection<String> result = new ArrayList<>();
        File ignorePackageFile = new File(path);

        if (ignorePackageFile.isFile() && ignorePackageFile.canRead()) {
            try {
                List<String> lines = Files.readLines(ignorePackageFile, Charset.defaultCharset());
                result.addAll(lines);
            } catch (IOException e) {
                throw new CryptoAnalysisParserException(
                        "Error while reading file " + ignorePackageFile + ": " + e.getMessage());
            }
        } else {
            throw new CryptoAnalysisParserException(
                    ignorePackageFile + " is not a file or cannot be read");
        }

        return result;
    }

    public String getApkFile() {
        return apkFile;
    }

    public void setApkFile(String apkFile) {
        this.apkFile = apkFile;
    }

    public String getPlatformDirectory() {
        return platformDirectory;
    }

    public void setPlatformDirectory(String platformDirectory) {
        this.platformDirectory = platformDirectory;
    }

    public String getRulesetDirectory() {
        return rulesetDirectory;
    }

    public void setRulesetDirectory(String rulesetDirectory) {
        this.rulesetDirectory = rulesetDirectory;
    }

    public CallGraphAlgorithm getCallGraphAlgorithm() {
        return callGraphAlgorithm;
    }

    public void setCallGraphAlgorithm(CallGraphAlgorithm algorithm) {
        this.callGraphAlgorithm = algorithm;
    }

    public Collection<Reporter.ReportFormat> getReportFormats() {
        return reportFormats;
    }

    public void setReportFormats(Collection<Reporter.ReportFormat> reportFormats) {
        this.reportFormats = new HashSet<>(reportFormats);
    }

    public String getReportPath() {
        return reportPath;
    }

    public void setReportPath(String reportPath) {
        this.reportPath = reportPath;
    }

    public boolean isVisualization() {
        return visualization;
    }

    public void setVisualization(boolean visualization) {
        this.visualization = visualization;
    }

    public Collection<String> getIgnoredSections() {
        return ignoredSections;
    }

    public void setIgnoredSections(Collection<String> ignoredSections) {
        this.ignoredSections = new HashSet<>(ignoredSections);
    }
    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }
    @Override
    public Integer call() throws Exception {
        return 0;
    }
}
