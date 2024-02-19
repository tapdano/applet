package tapdano;

import javacard.framework.*;

public interface TapDanoShareable extends Shareable {
  byte[] exec(byte origin, byte[] buf);
}