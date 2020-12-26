package cc.ejyf.platform.frameworkbase.util.tuples;

public class Tuple3<T, U, V> extends Tuple2<T, U> {
    public final V e3;

    public Tuple3(T e1, U e2, V e3) {
        super(e1, e2);
        this.e3 = e3;
    }
}
