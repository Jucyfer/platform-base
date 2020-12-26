package cc.ejyf.platform.frameworkbase.util.tuples;

public class Tuple4<T, U, V, W> extends Tuple3<T, U, V> {
    public final W e4;

    public Tuple4(T e1, U e2, V e3, W e4) {
        super(e1, e2, e3);
        this.e4 = e4;
    }
}
