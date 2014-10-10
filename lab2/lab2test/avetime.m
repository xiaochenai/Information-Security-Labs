x = average_3(1,:);
y1 = average_3(2,:);
y2 = average_3(3,:);
y3 = average_3(4,:);
y4 = average_3(5,:);
y5 = average_3(6,:);
y6 = average_3(7,:);
y7 = average_3(8,:);

figure(2);
plot(log(x),log(y1),'b');
hold on;
plot(log(x),log(y2),'g');
hold on;
plot(log(x),log(y3),'r');
hold on;
plot(log(x),log(y4),'c');
hold on;
plot(log(x),log(y5),'m');
hold on;
plot(log(x),log(y6),'y');
hold on;
plot(log(x),log(y7),'k');
hold on;
legend('Windows-PRNG','SHA1PRNG-SUN','ECDRBG128','ECDRBG256','MD5PRNG','HMACDRBG','SHA1PRNG-JsafeJCE');
title('1024 bit random number');
xlabel('log(x)');
ylabel('log(nanosecond)');