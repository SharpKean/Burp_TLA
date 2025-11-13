package ui;

import java.io.*;
import java.util.Properties;

public class Config {
    private static final String CONFIG_FILE = "config.properties";
    private static final String DB_FILE_KEY = "db_file";
    private static final String DIR_FILE_KEY = "dir_file";
    private static final String THREAD_NUM_KEY = "thread_num";
    private static final String TYPE_SCAN_KEY = "type_scan";
    private static final String FILTER_URL_KEY = "filter_url";
    private static final String XSS_ENABLE_KEY = "xss_enable";

    public static void updateConfig(String dbFilePath, String dirFilePath, String threadNum, String typeScan, String filterUrl, String xssEnable) {
        Properties properties = new Properties();

        try (InputStream inputStream = new FileInputStream(CONFIG_FILE)) {
            properties.load(inputStream);
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (dbFilePath != null) {
            properties.setProperty(DB_FILE_KEY, dbFilePath);
        }
        if (dirFilePath != null) {
            properties.setProperty(DIR_FILE_KEY, dirFilePath);
        }
        if (threadNum != null) {
            properties.setProperty(THREAD_NUM_KEY, threadNum);
        }
        if (typeScan != null) {
            properties.setProperty(TYPE_SCAN_KEY, typeScan);
        }
        if (xssEnable != null) {
            properties.setProperty(XSS_ENABLE_KEY, xssEnable);
        }
        if (filterUrl != null) {
            properties.setProperty(FILTER_URL_KEY, filterUrl);
        }

        try (OutputStream outputStream = new FileOutputStream(CONFIG_FILE)) {
            properties.store(outputStream, null);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public static void createConfigFile() {
        File configFile = new File("config.properties");
        if (!configFile.exists()) {
            try {
                configFile.createNewFile();
                FileWriter writer = new FileWriter(configFile);
                writer.write("# 初始化配置文件\n");
                writer.write("db_file=null\n");
                writer.write("dir_file=null\n");
                writer.write("thread_num=2\n");
                writer.write("type_scan=3\n");
                writer.write("xss_enable=false\n");
                writer.write("filter_url=['gov.com','google.com','firefoxchina.cn','googleapis.com','telemetry.mozilla.org','shodan.io']\n");
                writer.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }


    public static String getDBFile(String key) {
        Properties properties = new Properties();

        try (InputStream inputStream = new FileInputStream(CONFIG_FILE)) {
            properties.load(inputStream);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return properties.getProperty(key);
    }
}
