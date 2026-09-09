namespace AsmStone.Encoding;

internal static class A64ComplexRotation
{
    public static bool TryDecode(string type, uint encoded, out long angle)
    {
        angle = 0;
        if (type == "complexrotateop")
        {
            if (encoded > 3)
            {
                return false;
            }

            angle = encoded * 90L;
            return true;
        }

        if (type == "complexrotateopodd")
        {
            if (encoded > 1)
            {
                return false;
            }

            angle = 90 + encoded * 180L;
            return true;
        }

        return false;
    }

    public static bool TryEncode(string type, long angle, out uint encoded)
    {
        encoded = 0;
        if (type == "complexrotateop")
        {
            if (angle is not (0 or 90 or 180 or 270))
            {
                return false;
            }

            encoded = (uint)(angle / 90);
            return true;
        }

        if (type == "complexrotateopodd")
        {
            if (angle is not (90 or 270))
            {
                return false;
            }

            encoded = (uint)((angle - 90) / 180);
            return true;
        }

        return false;
    }
}
