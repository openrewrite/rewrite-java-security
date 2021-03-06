package org.openrewrite.java.security

import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import org.openrewrite.test.RecipeSpec
import org.openrewrite.test.RewriteTest

class ZipSlipTest: RewriteTest {
    override fun defaults(spec: RecipeSpec) {
        spec.recipe(ZipSlip(false))
    }

    @Test
    fun fixesZipSlipUsingFile()  = rewriteRun(
        java(
            """
            import java.io.File;
            import java.io.FileOutputStream;
            import java.io.RandomAccessFile;
            import java.io.FileWriter;
            import java.util.zip.ZipEntry;

            public class ZipTest {
                public void m1(ZipEntry entry, File dir) throws Exception {
                    String name = entry.getName();
                    File file = new File(dir, name);
                    FileOutputStream os = new FileOutputStream(file); // ZipSlip
                    RandomAccessFile raf = new RandomAccessFile(file, "rw"); // ZipSlip
                    FileWriter fw = new FileWriter(file); // ZipSlip
                }
            }
            """,
            """
            import java.io.File;
            import java.io.FileOutputStream;
            import java.io.RandomAccessFile;
            import java.io.FileWriter;
            import java.util.zip.ZipEntry;

            public class ZipTest {
                public void m1(ZipEntry entry, File dir) throws Exception {
                    String name = entry.getName();
                    File file = new File(dir, name);
                    if (!file.toPath().normalize().startsWith(dir.toPath())) {
                        throw new RuntimeException("Bad zip entry");
                    }
                    FileOutputStream os = new FileOutputStream(file); // ZipSlip
                    RandomAccessFile raf = new RandomAccessFile(file, "rw"); // ZipSlip
                    FileWriter fw = new FileWriter(file); // ZipSlip
                }
            }
            """
        )
    )

    @Test
    fun `fixes Zip Slip using Path`()  = rewriteRun(
        java(
            """
            import java.io.OutputStream;
            import java.io.RandomAccessFile;
            import java.io.FileWriter;
            import java.nio.file.Files;
            import java.nio.file.Path;
            import java.util.zip.ZipEntry;

            public class ZipTest {
                public void m1(ZipEntry entry, Path dir) throws Exception {
                    String name = entry.getName();
                    Path path = dir.resolve(name);
                    OutputStream os = Files.newOutputStream(path);
                }
            }
            """,
            """
            import java.io.OutputStream;
            import java.io.RandomAccessFile;
            import java.io.FileWriter;
            import java.nio.file.Files;
            import java.nio.file.Path;
            import java.util.zip.ZipEntry;

            public class ZipTest {
                public void m1(ZipEntry entry, Path dir) throws Exception {
                    String name = entry.getName();
                    Path path = dir.resolve(name);
                    if (!path.normalize().startsWith(dir)) {
                        throw new RuntimeException("Bad zip entry");
                    }
                    OutputStream os = Files.newOutputStream(path);
                }
            }
            """
        )
    )

    @Test
    fun `fixes Zip Slip using Path when creating a variable is required`()  = rewriteRun(
        java(
            """
            import java.io.OutputStream;
            import java.io.RandomAccessFile;
            import java.io.FileWriter;
            import java.nio.file.Files;
            import java.nio.file.Path;
            import java.util.zip.ZipEntry;

            public class ZipTest {
                public void m1(ZipEntry entry, Path dir) throws Exception {
                    String name = entry.getName();
                    OutputStream os = Files.newOutputStream(dir.resolve(name));
                }
            }
            """,
            """
            import java.io.OutputStream;
            import java.io.RandomAccessFile;
            import java.io.FileWriter;
            import java.nio.file.Files;
            import java.nio.file.Path;
            import java.util.zip.ZipEntry;

            public class ZipTest {
                public void m1(ZipEntry entry, Path dir) throws Exception {
                    String name = entry.getName();
                    final Path zipEntryPath = dir.resolve(name);
                    if (!zipEntryPath.normalize().startsWith(dir)) {
                        throw new RuntimeException("Bad zip entry");
                    }
                    OutputStream os = Files.newOutputStream(zipEntryPath);
                }
            }
            """
        )
    )

    @Test
    fun fixesZipSlipUsingString()  = rewriteRun(
        java(
            """
            import java.io.File;
            import java.io.FileOutputStream;
            import java.io.RandomAccessFile;
            import java.nio.file.Files;
            import java.util.zip.ZipEntry;

            public class ZipTest {
                public void m1(ZipEntry entry, File dir) throws Exception {
                    String name = entry.getName();
                    FileOutputStream os = new FileOutputStream(dir + File.separator + name); // ZipSlip
                }
            }
            """,
            """
            import java.io.File;
            import java.io.FileOutputStream;
            import java.io.RandomAccessFile;
            import java.nio.file.Files;
            import java.util.zip.ZipEntry;

            public class ZipTest {
                public void m1(ZipEntry entry, File dir) throws Exception {
                    String name = entry.getName();
                    final File zipEntryFile = new File(dir, name);
                    if (!zipEntryFile.toPath().normalize().startsWith(dir.toPath())) {
                        throw new RuntimeException("Bad zip entry");
                    }
                    FileOutputStream os = new FileOutputStream(zipEntryFile); // ZipSlip
                }
            }
            """
        )
    )

    @Test
    fun safeZipSlipPathStartsWith() = rewriteRun(
        java(
            """
            import java.io.FileOutputStream;
            import java.io.File;
            import java.nio.file.Path;
            import java.util.zip.ZipEntry;

            public class ZipTest {
              public void m2(ZipEntry entry, File dir) throws Exception {
                String name = entry.getName();
                File file = new File(dir, name);
                File canFile = file.getCanonicalFile();
                String canDir = dir.getCanonicalPath();
                if (!canFile.toPath().startsWith(canDir)) {
                  throw new Exception();
                }
                FileOutputStream os = new FileOutputStream(file); // OK
              }
            }
            """
        )
    )

    @Test
    fun safeZipSlipPathNormalizedStartsWith() = rewriteRun(
        java(
            """
            import java.io.File;
            import java.io.FileOutputStream;
            import java.util.zip.ZipEntry;

            public class ZipTest {
              public void m3(ZipEntry entry, File dir) throws Exception {
                String name = entry.getName();
                File file = new File(dir, name);
                if (!file.toPath().normalize().startsWith(dir.toPath()))
                  throw new Exception();
                FileOutputStream os = new FileOutputStream(file); // OK
              }
            }
            """
        )
    )

    @Test
    @Disabled("Need more global data flow and guard tracking")
    fun safeZipSlipValidateMethod() = rewriteRun(
        java(
            """
            import java.io.File;
            import java.io.FileOutputStream;
            import java.util.zip.ZipEntry;

            public class ZipTest {

              private void validate(File tgtdir, File file) throws Exception {
                File canFile = file.getCanonicalFile();
                if (!canFile.toPath().startsWith(tgtdir.toPath()))
                  throw new Exception();
              }

              public void m4(ZipEntry entry, File dir) throws Exception {
                String name = entry.getName();
                File file = new File(dir, name);
                validate(dir, file);
                FileOutputStream os = new FileOutputStream(file); // OK
              }
          }
          """
        )
    )

    @Test
    fun safeZipSlipPathAbsoluteNormalizeStartsWith() = rewriteRun(
        java(
            """
            import java.io.File;
            import java.io.FileOutputStream;
            import java.io.OutputStream;
            import java.nio.file.Path;
            import java.util.zip.ZipEntry;

            public class ZipTest {

              public void m5(ZipEntry entry, File dir) throws Exception {
                String name = entry.getName();
                File file = new File(dir, name);
                Path absfile = file.toPath().toAbsolutePath().normalize();
                Path absdir = dir.toPath().toAbsolutePath().normalize();
                if (!absfile.startsWith(absdir))
                  throw new Exception();
                OutputStream os = new FileOutputStream(file); // OK
              }
            }
            """
        )
    )

    @Test
    fun safeZipSlipSlipCanonicalPath() = rewriteRun(
        java(
            """
            import java.io.File;
            import java.io.OutputStream;
            import java.nio.file.Files;
            import java.nio.file.Path;
            import java.util.zip.ZipEntry;

            public class ZipTest {

              public void m6(ZipEntry entry, Path dir) throws Exception {
                String canonicalDest = dir.toFile().getCanonicalPath();
                Path target = dir.resolve(entry.getName());
                String canonicalTarget = target.toFile().getCanonicalPath();
                if (!canonicalTarget.startsWith(canonicalDest + File.separator))
                  throw new Exception();
                OutputStream os = Files.newOutputStream(target); // OK
              }
            }
            """
        )
    )

    @Test
    fun `example data-label-system-backend`() = rewriteRun(
        java(
            """
            import java.io.File;
            import java.io.FileInputStream;
            import java.io.FileOutputStream;
            import java.io.BufferedInputStream;
            import java.io.BufferedOutputStream;
            import java.io.InputStream;
            import java.io.OutputStream;
            import java.io.IOException;
            import java.util.ArrayList;
            import java.util.List;
            import java.util.zip.ZipEntry;
            import java.util.zip.ZipInputStream;

            public class FileHandleUtil {

                public static final int BUFFER_SIZE = 1024;
                /**
                 * ?????? zip ??????
                 */
                public static List<String> unZip(File zipFile, String destDir) throws Exception {
                    // ?????? destDir ??? null, ????????????, ??????????????????, ????????????????????????????????????
                    if(destDir == null || destDir.trim().length() == 0) {
                        destDir = zipFile.getParent();
                    }

                    destDir = destDir.endsWith(File.separator) ? destDir : destDir + File.separator;
                    List<String> fileNames = new ArrayList<String>();

                    try(ZipInputStream is = new ZipInputStream(new BufferedInputStream(new FileInputStream(zipFile), BUFFER_SIZE))) {
                        ZipEntry entry = null;
                        while ((entry = is.getNextEntry()) != null) {
                            fileNames.add(entry.getName());

                            if (entry.isDirectory()) {
                                File directory = new File(destDir, entry.getName());
                                directory.mkdirs();
                            } else {
                                OutputStream os = null;
                                try {
                                    os = new BufferedOutputStream(new FileOutputStream(new File(destDir, entry.getName())), BUFFER_SIZE);
                                    copy(is, os);
                                } finally {
                                    if (os != null) {
                                        os.close();
                                    }
                                }
                            }
                        }
                    } catch(Exception e) {
                        throw e;
                    }
                    return fileNames;
                }

                static void copy(InputStream source, OutputStream target) throws IOException {
                    byte[] buf = new byte[8192];
                    int length;
                    while ((length = source.read(buf)) > 0) {
                        target.write(buf, 0, length);
                    }
                }

            }
            """,
            """
            import java.io.File;
            import java.io.FileInputStream;
            import java.io.FileOutputStream;
            import java.io.BufferedInputStream;
            import java.io.BufferedOutputStream;
            import java.io.InputStream;
            import java.io.OutputStream;
            import java.io.IOException;
            import java.util.ArrayList;
            import java.util.List;
            import java.util.zip.ZipEntry;
            import java.util.zip.ZipInputStream;

            public class FileHandleUtil {

                public static final int BUFFER_SIZE = 1024;
                /**
                 * ?????? zip ??????
                 */
                public static List<String> unZip(File zipFile, String destDir) throws Exception {
                    // ?????? destDir ??? null, ????????????, ??????????????????, ????????????????????????????????????
                    if(destDir == null || destDir.trim().length() == 0) {
                        destDir = zipFile.getParent();
                    }

                    destDir = destDir.endsWith(File.separator) ? destDir : destDir + File.separator;
                    List<String> fileNames = new ArrayList<String>();

                    try(ZipInputStream is = new ZipInputStream(new BufferedInputStream(new FileInputStream(zipFile), BUFFER_SIZE))) {
                        ZipEntry entry = null;
                        while ((entry = is.getNextEntry()) != null) {
                            fileNames.add(entry.getName());

                            if (entry.isDirectory()) {
                                File directory = new File(destDir, entry.getName());
                                directory.mkdirs();
                            } else {
                                OutputStream os = null;
                                try {
                                    final File zipEntryFile = new File(destDir, entry.getName());
                                    if (!zipEntryFile.toPath().normalize().startsWith(destDir)) {
                                        throw new RuntimeException("Bad zip entry");
                                    }
                                    os = new BufferedOutputStream(new FileOutputStream(zipEntryFile), BUFFER_SIZE);
                                    copy(is, os);
                                } finally {
                                    if (os != null) {
                                        os.close();
                                    }
                                }
                            }
                        }
                    } catch(Exception e) {
                        throw e;
                    }
                    return fileNames;
                }

                static void copy(InputStream source, OutputStream target) throws IOException {
                    byte[] buf = new byte[8192];
                    int length;
                    while ((length = source.read(buf)) > 0) {
                        target.write(buf, 0, length);
                    }
                }

            }
            """
        )
    )

    @Test
    fun `example jbake`() = rewriteRun(
        java(
            """
            import java.io.File;
            import java.io.FileOutputStream;
            import java.io.IOException;
            import java.io.InputStream;
            import java.util.zip.ZipEntry;
            import java.util.zip.ZipInputStream;

            /**
             * Provides Zip file related functions
             *
             * @author Jonathan Bullock <a href="mailto:jonbullock@gmail.com">jonbullock@gmail.com</a>
             *
             */
            public class ZipUtil {

                /**
                 * Extracts content of Zip file to specified output path.
                 *
                 * @param is             {@link InputStream} InputStream of Zip file
                 * @param outputFolder    folder where Zip file should be extracted to
                 * @throws IOException    if IOException occurs
                 */
                public static void extract(InputStream is, File outputFolder) throws IOException {
                    ZipInputStream zis = new ZipInputStream(is);
                    ZipEntry entry;
                    byte[] buffer = new byte[1024];

                    while ((entry = zis.getNextEntry()) != null) {
                        File outputFile = new File(outputFolder.getCanonicalPath() + File.separatorChar + entry.getName());
                        File outputParent = new File(outputFile.getParent());
                        outputParent.mkdirs();

                        if (entry.isDirectory()) {
                            if (!outputFile.exists()) {
                                outputFile.mkdir();
                            }
                        } else {
                            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                                int len;
                                while ((len = zis.read(buffer)) > 0) {
                                    fos.write(buffer, 0, len);
                                }
                            }
                        }
                    }
                }
            }
            """,
            """
            import java.io.File;
            import java.io.FileOutputStream;
            import java.io.IOException;
            import java.io.InputStream;
            import java.util.zip.ZipEntry;
            import java.util.zip.ZipInputStream;

            /**
             * Provides Zip file related functions
             *
             * @author Jonathan Bullock <a href="mailto:jonbullock@gmail.com">jonbullock@gmail.com</a>
             *
             */
            public class ZipUtil {

                /**
                 * Extracts content of Zip file to specified output path.
                 *
                 * @param is             {@link InputStream} InputStream of Zip file
                 * @param outputFolder    folder where Zip file should be extracted to
                 * @throws IOException    if IOException occurs
                 */
                public static void extract(InputStream is, File outputFolder) throws IOException {
                    ZipInputStream zis = new ZipInputStream(is);
                    ZipEntry entry;
                    byte[] buffer = new byte[1024];

                    while ((entry = zis.getNextEntry()) != null) {
                        File outputFile = new File(outputFolder.getCanonicalPath(), entry.getName());
                        if (!outputFile.toPath().normalize().startsWith(outputFolder.getCanonicalPath())) {
                            throw new RuntimeException("Bad zip entry");
                        }
                        File outputParent = new File(outputFile.getParent());
                        outputParent.mkdirs();

                        if (entry.isDirectory()) {
                            if (!outputFile.exists()) {
                                outputFile.mkdir();
                            }
                        } else {
                            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                                int len;
                                while ((len = zis.read(buffer)) > 0) {
                                    fos.write(buffer, 0, len);
                                }
                            }
                        }
                    }
                }
            }
            """
        )
    )

    @Test
    fun `example intranet_app_manager`() = rewriteRun(
        java(
            """
            package org.yzr.utils.file;

            import java.io.File;
            import java.io.FileOutputStream;
            import java.io.InputStream;
            import java.util.Enumeration;
            import java.util.zip.ZipEntry;
            import java.util.zip.ZipFile;

            public class ZipUtil {

                public static String unzip(String path) {
                    try {
                        long start = System.currentTimeMillis();
                        String destDirPath = System.getProperty("java.io.tmpdir") + File.separator + start;
                        ZipFile zipFile = new ZipFile(path);
                        Enumeration<?> entries = zipFile.entries();
                        while (entries.hasMoreElements()) {
                            ZipEntry entry = (ZipEntry) entries.nextElement();
                            if (entry.isDirectory()) {
                                String dirPath = destDirPath + File.separator + entry.getName();
                                File dir = new File(dirPath);
                                dir.mkdirs();
                            } else {
                                File targetFile = new File(destDirPath + File.separator + entry.getName());
                                if (!targetFile.getParentFile().exists()) {
                                    targetFile.getParentFile().mkdirs();
                                }
                                targetFile.createNewFile();
                                InputStream is = zipFile.getInputStream(entry);
                                FileOutputStream fos = new FileOutputStream(targetFile);
                                int len;
                                byte[] buf = new byte[1024];
                                while ((len = is.read(buf)) != -1) {
                                    fos.write(buf, 0, len);
                                }
                                fos.close();
                                is.close();
                            }
                        }
                        zipFile.close();
                        return destDirPath;
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    return null;
                }
            }
            """,
            """
            package org.yzr.utils.file;

            import java.io.File;
            import java.io.FileOutputStream;
            import java.io.InputStream;
            import java.util.Enumeration;
            import java.util.zip.ZipEntry;
            import java.util.zip.ZipFile;

            public class ZipUtil {

                public static String unzip(String path) {
                    try {
                        long start = System.currentTimeMillis();
                        String destDirPath = System.getProperty("java.io.tmpdir") + File.separator + start;
                        ZipFile zipFile = new ZipFile(path);
                        Enumeration<?> entries = zipFile.entries();
                        while (entries.hasMoreElements()) {
                            ZipEntry entry = (ZipEntry) entries.nextElement();
                            if (entry.isDirectory()) {
                                String dirPath = destDirPath + File.separator + entry.getName();
                                File dir = new File(dirPath);
                                dir.mkdirs();
                            } else {
                                File targetFile = new File(destDirPath, entry.getName());
                                if (!targetFile.toPath().normalize().startsWith(destDirPath)) {
                                    throw new RuntimeException("Bad zip entry");
                                }
                                if (!targetFile.getParentFile().exists()) {
                                    targetFile.getParentFile().mkdirs();
                                }
                                targetFile.createNewFile();
                                InputStream is = zipFile.getInputStream(entry);
                                FileOutputStream fos = new FileOutputStream(targetFile);
                                int len;
                                byte[] buf = new byte[1024];
                                while ((len = is.read(buf)) != -1) {
                                    fos.write(buf, 0, len);
                                }
                                fos.close();
                                is.close();
                            }
                        }
                        zipFile.close();
                        return destDirPath;
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    return null;
                }
            }
            """
        )
    )

    @Test
    fun `example infowangxin_springmvc`() = rewriteRun(
        java(
            """
            import java.io.BufferedInputStream;
            import java.io.BufferedOutputStream;
            import java.io.File;
            import java.io.FileInputStream;
            import java.io.FileOutputStream;
            import java.io.IOException;
            import java.io.InputStream;
            import java.io.OutputStream;
            import java.util.Enumeration;
            import java.util.List;
            import java.util.zip.CRC32;
            import java.util.zip.CheckedOutputStream;
            import java.util.zip.Deflater;
            import java.util.zip.ZipEntry;
            import java.util.zip.ZipFile;
            import java.util.zip.ZipOutputStream;

            class ZipUtil {
                    /**
                     * ?????????
                     *
                     * @param zipfile
                     *            File ????????????????????????
                     * @param descDir
                     *            String ????????????????????????
                     */
                    @SuppressWarnings({ "rawtypes", "resource" })
                    public static void unZipFiles(File zipfile, String descDir) {
                        try {
                            ZipFile zf = new ZipFile(zipfile);
                            ZipEntry entry = null;
                            String zipEntryName = null;
                            InputStream in = null;
                            OutputStream out = null;
                            byte[] buf1 = null;
                            int len;
                            for (Enumeration entries = zf.entries(); entries.hasMoreElements();) {
                                entry = ((ZipEntry) entries.nextElement());
                                zipEntryName = entry.getName();
                                in = zf.getInputStream(entry);
                                out = new FileOutputStream(descDir + zipEntryName);
                                buf1 = new byte[1024];
                                len = 0;
                                while ((len = in.read(buf1)) > 0) {
                                    out.write(buf1, 0, len);
                                }
                                in.close();
                                out.close();
                            }
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
            }
            """,
            """
            import java.io.BufferedInputStream;
            import java.io.BufferedOutputStream;
            import java.io.File;
            import java.io.FileInputStream;
            import java.io.FileOutputStream;
            import java.io.IOException;
            import java.io.InputStream;
            import java.io.OutputStream;
            import java.util.Enumeration;
            import java.util.List;
            import java.util.zip.CRC32;
            import java.util.zip.CheckedOutputStream;
            import java.util.zip.Deflater;
            import java.util.zip.ZipEntry;
            import java.util.zip.ZipFile;
            import java.util.zip.ZipOutputStream;

            class ZipUtil {
                    /**
                     * ?????????
                     *
                     * @param zipfile
                     *            File ????????????????????????
                     * @param descDir
                     *            String ????????????????????????
                     */
                    @SuppressWarnings({ "rawtypes", "resource" })
                    public static void unZipFiles(File zipfile, String descDir) {
                        try {
                            ZipFile zf = new ZipFile(zipfile);
                            ZipEntry entry = null;
                            String zipEntryName = null;
                            InputStream in = null;
                            OutputStream out = null;
                            byte[] buf1 = null;
                            int len;
                            for (Enumeration entries = zf.entries(); entries.hasMoreElements();) {
                                entry = ((ZipEntry) entries.nextElement());
                                zipEntryName = entry.getName();
                                in = zf.getInputStream(entry);
                                final File zipEntryFile = new File(descDir, zipEntryName);
                                if (!zipEntryFile.toPath().normalize().startsWith(descDir)) {
                                    throw new RuntimeException("Bad zip entry");
                                }
                                out = new FileOutputStream(zipEntryFile);
                                buf1 = new byte[1024];
                                len = 0;
                                while ((len = in.read(buf1)) > 0) {
                                    out.write(buf1, 0, len);
                                }
                                in.close();
                                out.close();
                            }
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
            }
            """
        )
    )

    @Test
    fun `example fortify-coudscan-plugin`() = rewriteRun(
        java(
            """
            import java.io.File;
            import java.io.FileInputStream;
            import java.io.FileNotFoundException;
            import java.io.FileOutputStream;
            import java.io.IOException;
            import java.util.zip.ZipEntry;
            import java.util.zip.ZipInputStream;

            public class ArchiveUtil {

                private ArchiveUtil() {}


                public static void unzip(File directory, File zipFile) throws IOException {
                    if(!directory.exists()) {
                        directory.mkdirs();
                    }
                    byte[] buffer = new byte[2048];

                    try (final FileInputStream fInput = new FileInputStream(zipFile);
                         final ZipInputStream zipInput = new ZipInputStream(fInput)) {

                        ZipEntry entry = zipInput.getNextEntry();
                        while (entry != null) {
                            String entryName = entry.getName();
                            File file = new File(directory.getAbsolutePath() + File.separator + entryName);

                            // Validate against potentially malicious zip payload
                            // https://vulncat.fortify.com/en/detail?id=desc.controlflow.java.path_manipulation_zip_entry_overwrite
                            if (!file.getCanonicalPath().startsWith(directory.getCanonicalPath())) {
                                throw new IOException("The archive contains an entry that would be extracted outside of the target directory.");
                            }

                            if (entry.isDirectory()) {
                                File newDir = new File(file.getAbsolutePath());
                                if (!newDir.exists()) {
                                    newDir.mkdirs();
                                }
                            } else {
                                if (!file.getParentFile().isDirectory() && !file.getParentFile().exists()) {
                                    file.getParentFile().mkdirs();
                                }
                                try (FileOutputStream fOutput = new FileOutputStream(file)) {
                                    int count;
                                    while ((count = zipInput.read(buffer)) > 0) {
                                        fOutput.write(buffer, 0, count);
                                    }
                                }
                            }
                            zipInput.closeEntry();
                            entry = zipInput.getNextEntry();
                        }
                        zipInput.closeEntry();
                    } catch (IOException e) {
                        throw new IOException(e);
                    }
                }

            }
            """,
            """
            import java.io.File;
            import java.io.FileInputStream;
            import java.io.FileNotFoundException;
            import java.io.FileOutputStream;
            import java.io.IOException;
            import java.util.zip.ZipEntry;
            import java.util.zip.ZipInputStream;

            public class ArchiveUtil {

                private ArchiveUtil() {}


                public static void unzip(File directory, File zipFile) throws IOException {
                    if(!directory.exists()) {
                        directory.mkdirs();
                    }
                    byte[] buffer = new byte[2048];

                    try (final FileInputStream fInput = new FileInputStream(zipFile);
                         final ZipInputStream zipInput = new ZipInputStream(fInput)) {

                        ZipEntry entry = zipInput.getNextEntry();
                        while (entry != null) {
                            String entryName = entry.getName();
                            File file = new File(directory.getAbsolutePath() + File.separator + entryName);

                            // Validate against potentially malicious zip payload
                            // https://vulncat.fortify.com/en/detail?id=desc.controlflow.java.path_manipulation_zip_entry_overwrite
                            if (!file.getCanonicalFile().toPath().startsWith(directory.getCanonicalFile().toPath())) {
                                throw new IOException("The archive contains an entry that would be extracted outside of the target directory.");
                            }

                            if (entry.isDirectory()) {
                                File newDir = new File(file.getAbsolutePath());
                                if (!newDir.exists()) {
                                    newDir.mkdirs();
                                }
                            } else {
                                if (!file.getParentFile().isDirectory() && !file.getParentFile().exists()) {
                                    file.getParentFile().mkdirs();
                                }
                                try (FileOutputStream fOutput = new FileOutputStream(file)) {
                                    int count;
                                    while ((count = zipInput.read(buffer)) > 0) {
                                        fOutput.write(buffer, 0, count);
                                    }
                                }
                            }
                            zipInput.closeEntry();
                            entry = zipInput.getNextEntry();
                        }
                        zipInput.closeEntry();
                    } catch (IOException e) {
                        throw new IOException(e);
                    }
                }

            }
            """
        )
    )

    @Test
    @Disabled("Generates an unexpected diff")
    fun `example kindling`() = rewriteRun(
        java(
            """
            import java.io.File;
            import java.io.InputStream;
            import java.io.FileInputStream;
            import java.io.FileNotFoundException;
            import java.io.FileOutputStream;
            import java.io.IOException;
            import java.io.OutputStream;
            import java.util.Enumeration;
            import java.util.zip.ZipFile;
            import java.util.zip.ZipEntry;
            import java.util.zip.ZipInputStream;

            class Test {
              static final int BUFFER = 2048;

              private void extractZip(String src, String dest) throws Exception {
            	  ZipFile zf = new ZipFile(src);
            	  try {
            		  for (Enumeration<? extends ZipEntry> e = zf.entries(); e.hasMoreElements();) {
            			  ZipEntry ze = e.nextElement();
            			  String name = ze.getName();
            			  if (name.endsWith(".html") || name.endsWith(".htm") || name.endsWith(".png") || name.endsWith(".css")) {
            				  InputStream in = zf.getInputStream(ze);
            				  OutputStream out = new FileOutputStream(dest+name);

            				  byte data[] = new byte[BUFFER];
            				  int count;
            				  while((count = in.read(data, 0, BUFFER)) != -1) {
            					  out.write(data, 0, count);
            				  }

            				  out.close();
            				  in.close();
            			  }
            		  }
            	  } finally {
            		  zf.close();
            	  }
              }
            }
            """.trimIndent(),
            """
            import java.io.File;
            import java.io.InputStream;
            import java.io.FileInputStream;
            import java.io.FileNotFoundException;
            import java.io.FileOutputStream;
            import java.io.IOException;
            import java.io.OutputStream;
            import java.util.Enumeration;
            import java.util.zip.ZipFile;
            import java.util.zip.ZipEntry;
            import java.util.zip.ZipInputStream;

            class Test {
              static final int BUFFER = 2048;

              private void extractZip(String src, String dest) throws Exception {
            	  ZipFile zf = new ZipFile(src);
            	  try {
            		  for (Enumeration<? extends ZipEntry> e = zf.entries(); e.hasMoreElements();) {
            			  ZipEntry ze = e.nextElement();
            			  String name = ze.getName();
            			  if (name.endsWith(".html") || name.endsWith(".htm") || name.endsWith(".png") || name.endsWith(".css")) {
            				  InputStream in = zf.getInputStream(ze);
            				  final File zipEntryFile = new File(dest, name);
            				  if (!zipEntryFile.toPath().normalize().startsWith(dest)) {
            					  throw new RuntimeException("Bad zip entry");
            				  }
            				  OutputStream out = new FileOutputStream(zipEntryFile);

            				  byte data[] = new byte[BUFFER];
            				  int count;
            				  while((count = in.read(data, 0, BUFFER)) != -1) {
            					  out.write(data, 0, count);
            				  }

            				  out.close();
            				  in.close();
            			  }
            		  }
            	  } finally {
            		  zf.close();
            	  }
              }
            }
            """.trimIndent()
        )
    )
}
