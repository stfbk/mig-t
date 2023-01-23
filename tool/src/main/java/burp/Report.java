package burp;

import be.quodlibet.boxable.BaseTable;
import be.quodlibet.boxable.Cell;
import be.quodlibet.boxable.Row;
import be.quodlibet.boxable.datatable.DataTable;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;

import java.awt.*;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Class used to generate a report for a test
 *
 * @author Matteo Bitussi
 */
public class Report {

    public void toPdf() throws IOException {
        String message = "Test Report";
        try (PDDocument doc = new PDDocument())
        {
            PDPage page = new PDPage();


            try (PDPageContentStream contents = new PDPageContentStream(doc, page))
            {
                contents.beginText();
                contents.setFont(PDType1Font.HELVETICA_BOLD, 12);
                contents.newLineAtOffset(100, 700);
                contents.showText(message);
                contents.endText();
            }

            //Source: github.com/dhorions/boxable

            //Dummy Table
            float margin = 50;
// starting y position is whole page height subtracted by top and bottom margin
            float yStartNewPage = page.getMediaBox().getHeight() - (2 * margin);
// we want table across whole page width (subtracted by left and right margin ofcourse)
            float tableWidth = page.getMediaBox().getWidth() - (2 * margin);

            BaseTable table = new BaseTable(550, yStartNewPage, 70, tableWidth, margin, doc, page, true,
                    true);
            //Create Header row
            Row<PDPage> headerRow = table.createRow(15f);
            Cell<PDPage> cell = headerRow.createCell(100, "Awesome Facts About Belgium");
            cell.setFont(PDType1Font.HELVETICA_BOLD);
            cell.setFillColor(Color.BLACK);
            table.addHeaderRow(headerRow);

            Row<PDPage> row = table.createRow(12);
            cell = row.createCell(30, "Test 1");
            cell = row.createCell(70, "Some value");

            table.draw();

            doc.addPage(page);

            doc.save("testfile.pdf");
            doc.close();
        }
    }
}
