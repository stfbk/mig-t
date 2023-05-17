import burp.ParsingException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class Checks_Test {

    @Test
    @DisplayName("parser")
    void test_parser() throws ParsingException {
        String input = "{\n" +
                "  \"pageInfo\": {\n" +
                "    \"pageName\": \"abc\",\n" +
                "    \"pagePic\": \"http://example.com/content.jpg\"\n" +
                "  },\n" +
                "  \"posts\": [\n" +
                "    {\n" +
                "      \"post_id\": \"123456789012_123456789012\",\n" +
                "      \"actor_id\": \"1234567890\",\n" +
                "      \"picOfPersonWhoPosted\": \"http://example.com/photo.jpg\",\n" +
                "      \"nameOfPersonWhoPosted\": \"Jane Doe\",\n" +
                "      \"message\": \"Sounds cool. Can't wait to see it!\",\n" +
                "      \"likesCount\": \"2\",\n" +
                "      \"comments\": [],\n" +
                "      \"timeOfPost\": \"1234567890\"\n" +
                "    }\n" +
                "  ]\n" +
                "}";


    }
}
