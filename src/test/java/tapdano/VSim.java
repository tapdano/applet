package tapdano;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.remote.VSmartCard;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;

import java.lang.reflect.Field;

/**
 * Launches jcardsim with VSmartCard connectivity
 */
public class VSim {

    static final int PORT = 35964;

    static final byte[] AID_TapDano = {(byte) 0x08, (byte) 0x54, (byte) 0x61, (byte) 0x70, (byte) 0x44, (byte) 0x61, (byte) 0x6E, (byte) 0x6F, (byte) 0x01};
    static final byte[] AID_FIDO =    {(byte) 0x08, (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x06, (byte) 0x47, (byte) 0x2F, (byte) 0x00, (byte) 0x01};
    static final byte[] AID_NDEF =    {(byte) 0x07, (byte) 0xD2, (byte) 0x76, (byte) 0x00, (byte) 0x00, (byte) 0x85, (byte) 0x01, (byte) 0x01};

    static final AID appletAID_TapDano = AIDUtil.create("54617044616E6F01");
    static final AID appletAID_FIDO2 = AIDUtil.create("A0000006472F0001");
    static final AID appletAID_NDEF = AIDUtil.create("D2760000850101");

    public static Simulator startBackgroundSimulator() throws Exception {
        System.setProperty("com.licel.jcardsim.vsmartcard.reloader.port", "" + PORT);
        System.setProperty("com.licel.jcardsim.vsmartcard.reloader.delay", "1000");

        VSmartCard sc = new VSmartCard("127.0.0.1", PORT);

        // The JCardSim VSmartCard class doesn't natively support loading applets at startup...
        // ... and it also doesn't provide access to the Simulator class necessary to do that!
        // To avoid needing to patch VCardSim, we'll violate Java member visibility rules
        // and reach directly into the class to install our applet.
        Field f = sc.getClass().getDeclaredField("sim");
        f.setAccessible(true);
        return (Simulator) f.get(sc);
    }

    public static synchronized void installApplet(Simulator sim) {
        sim.installApplet(appletAID_TapDano, AppletInstaller.class, AID_TapDano, (short)0, (byte)AID_TapDano.length);
        sim.installApplet(appletAID_FIDO2, AppletInstaller.class, AID_FIDO, (short)0, (byte)AID_FIDO.length);
        sim.installApplet(appletAID_NDEF, AppletInstaller.class, AID_NDEF, (short)0, (byte)AID_NDEF.length);
        //sim.selectApplet(appletAID_TapDano);
    }

    public static Simulator startForegroundSimulator() {
        return new Simulator();
    }

    public static synchronized byte[] transmitCommand(Simulator sim, byte[] command) {
        return sim.transmitCommand(command);
    }

    public static synchronized void softReset(Simulator sim) {
        sim.reset();
        //sim.selectApplet(appletAID_TapDano);
    }

    public static void main(String[] args) throws Exception {
        Simulator sim = startBackgroundSimulator();
        installApplet(sim);
    }

}