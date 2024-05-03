package tapdano;

import javacard.framework.*;

public interface TapDanoShareable extends Shareable {
  short exec(byte origin, byte[] buffer, byte offset);
}