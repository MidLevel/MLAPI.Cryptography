using MLAPI.Cryptography.Math;

namespace MLAPI.Cryptography.EllipticCurves
{
    public class CurvePoint
    {
        public static readonly CurvePoint POINT_AT_INFINITY = new CurvePoint();
        public BigInteger X { get; private set; }
        public BigInteger Y { get; private set; }
        private readonly bool pai = false;

        public CurvePoint(BigInteger x, BigInteger y)
        {
            X = x;
            Y = y;
        }

        private CurvePoint()
        {
            pai = true;
        } // Accessing corrdinates causes undocumented behaviour

        public override string ToString()
        {
            return pai ? "(POINT_AT_INFINITY)" : "(" + X + ", " + Y + ")";
        }
    }
}
