package cc.ejyf.platform.frameworkbase.util.tuples;

public class Tuple5<T, U, V, W, X> extends Tuple4<T, U, V, W> {
    public final X e5;

    public Tuple5(T e1, U e2, V e3, W e4, X e5) {
        super(e1, e2, e3, e4);
        this.e5 = e5;
    }
}
