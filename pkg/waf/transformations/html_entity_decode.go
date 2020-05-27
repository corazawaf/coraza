package transformations
import(
	"html"
)

func HtmlEntityDecode(data string) string{
	return html.UnescapeString(data)
}