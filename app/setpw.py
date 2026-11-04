"""Generate (or set) the Tresorry passphrase and write its scrypt hash.

Usage: setpw.py            -> generates a random passphrase and prints it once
       setpw.py --stdin    -> reads your own passphrase from stdin
"""
import hashlib
import math
import os
import secrets
import sys
from pathlib import Path

WORDS = sorted(set("""
acorn amber anchor apple apricot arrow atlas attic autumn avocado badger bagel bakery balloon bamboo
banana banjo barley barrel basil basket beacon beaver beetle berry bicycle biscuit blanket blender
blossom bonfire bottle boulder bramble breeze brick bridge brownie bubble bucket buffalo bugle bunny
burrito butter button cabbage cabin cactus camel camera candle canoe canvas canyon caramel carbon
carpet carrot castle catnip cedar cello cereal chalk cheddar cherry chestnut chimney chipmunk cider
cinnamon circus citrus clover cobalt cobra cocoa coconut comet compass cookie copper coral cotton
cougar cowboy coyote crayon cricket crocus crouton crystal cupcake curtain cyclone daisy dancer
delta denim desert diamond dingo dolphin domino donkey donut dragon drizzle dumpling eagle easel echo
eclipse eggplant elbow ember emerald engine espresso falcon falafel feather fennel ferret fiddle
fjord flamingo flannel fondue forest fossil fountain freckle frisbee fudge galaxy garden garlic gazebo
gecko geyser ginger giraffe glacier glitter globe goblin gondola gopher granite grape gravy guitar
gumbo hammock hamster harbor harvest hazel hedgehog helmet heron hickory hippo honey hopscotch hornet
hummus husky iceberg igloo iguana island ivory jacket jaguar jasmine jelly jigsaw jukebox jungle
kayak kazoo kettle kiwi koala ladder lagoon lantern lasagna lava lemon lentil lettuce lily lizard
llama lobster locket lollipop lotus macaron magnet magpie mango maple marble marmot meadow meerkat
melon meteor mint mirror mitten mocha monsoon moose mosaic muffin mustang mustard nacho napkin nectar
needle nickel noodle nugget nutmeg oasis oatmeal ocean octopus olive omelet onion opal orbit orchid
origami ostrich otter oyster paddle pagoda pancake panda papaya parrot parsley pasta peach peanut
pebble pelican penguin pepper pickle pigeon pillow pinecone pistachio pixel pizza planet plum pocket
polka pony popcorn porcupine potato pretzel prism puddle puffin pumpkin puzzle quartz quiche quill
quokka rabbit raccoon radar radish raisin raven ravioli reindeer ribbon rocket rodeo rooster ruby
saddle saffron salmon salsa sandal sardine satchel saturn scarf scooter seagull sequoia shadow
shamrock sherbet shovel silver skillet sloth snail snowman socket sombrero sparrow spinach sponge
spruce squash squid stapler starfish sudoku summit sunset sushi swan tadpole taco tamale tango teapot
thimble thunder tiger timber toast toffee tomato topaz tornado tortilla toucan tractor trumpet tulip
tundra turnip turtle tuxedo ukulele umbrella unicorn valley vanilla velvet violin volcano waffle
walnut walrus wasabi whale whisker whistle willow window wizard wombat yeti yodel yogurt zebra zeppelin
zigzag zucchini
""".split()))

N_WORDS = 4
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1


def make_hash(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                        maxmem=128 * 1024 * 1024, dklen=32)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${dk.hex()}"


def main():
    if "--stdin" in sys.argv:
        pw = sys.stdin.readline().rstrip("\n")
        if len(pw) < 12:
            sys.exit("passphrase must be at least 12 characters")
        bits = None
    else:
        words = [secrets.choice(WORDS) for _ in range(N_WORDS)]
        pw = "-".join(words + [f"{secrets.randbelow(100):02d}"])
        bits = N_WORDS * math.log2(len(WORDS)) + math.log2(100)
    out = Path(os.environ.get("OUT", "/out/password_hash"))
    tmp = out.with_suffix(".tmp")
    tmp.write_text(make_hash(pw) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, out)
    print(f"PASSPHRASE: {pw}")
    if bits:
        print(f"(~{bits:.0f} bits of entropy, {len(WORDS)}-word list, online guessing capped at 10/min)")


if __name__ == "__main__":
    main()
