import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.security.ProtectionDomain;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;

public class StaticMethodListerAgent {


    private static final Set<String> loadedClassNames = new ConcurrentSkipListSet<>();
    private static final String ANSI_RESET = "\u001B[0m";
    private static final String ANSI_YELLOW = "\u001B[33m";
    private static final String ANSI_CYAN = "\u001B[36m";
    private static final String ANSI_GREEN = "\u001B[32m";

    public static void premain(String agentArgs, Instrumentation inst) {
        inst.addTransformer(new ClassFileTransformer() {
            @Override
            public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                    ProtectionDomain protectionDomain, byte[] classfileBuffer) {
                loadedClassNames.add(className.replace('/', '.'));
                return null;
            }
        });

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            listStaticMethods();
        }));
    }

    private static void listStaticMethods() {
        for (String className : loadedClassNames) {
            try {
                Class<?> clazz = Class.forName(className);

                for (Method method : clazz.getDeclaredMethods()) {
                    if (Modifier.isStatic(method.getModifiers())) {
                        StringBuilder methodSignature = new StringBuilder();

                        methodSignature.append(ANSI_YELLOW).append(method.getName()).append(ANSI_RESET);
                        methodSignature.append("(");

                        Class<?>[] parameterTypes = method.getParameterTypes();
                        for (int i = 0; i < parameterTypes.length; i++) {
                            methodSignature.append(ANSI_CYAN).append(parameterTypes[i].getSimpleName()).append(ANSI_RESET);
                            if (i < parameterTypes.length - 1) {
                                methodSignature.append(", ");
                            }
                        }
                        methodSignature.append(")");

                        methodSignature.append(" -> ").append(ANSI_GREEN).append(method.getReturnType().getSimpleName()).append(ANSI_RESET);

                        System.out.println(clazz.getName() + "." + methodSignature.toString());
                    }
                }
            } catch (Throwable e) {
                System.err.println("Could not inspect class: " + className);
                e.printStackTrace();
            }
        }
    }
}
