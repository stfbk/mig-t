import burp.Report;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;

public class Report_Test {

    @Test
    @DisplayName("ParsingRawSessionAction test")
    void test_toPdf() throws IOException {
        Report r = new Report();

        r.toPdf();
    }
}
