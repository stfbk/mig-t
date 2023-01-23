package burp;

/**
 * Class used to mark User Actions to be managed by session actions
 *
 * @author Matteo Bitussi
 */
public class Marker {
    String name;

    /**
     * Constructor to instantiate a new marker object
     * @param _name name of the marker
     */
    public Marker(String _name) {
        name = _name;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Marker marker = (Marker) o;

        return name != null ? name.equals(marker.name) : marker.name == null;
    }
}